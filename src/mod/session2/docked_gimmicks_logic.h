#pragma once
// P8 session 28: the gimmicks docked to a player character (docs/research/s25/gimmicks-dueno.md, section 6
// "Implementado"). The pure logic, with no game access, so the tests can run it on S27's real 2005 bytes.
// Builds 1.0.0.2976, 1.0.0.3527 and 1.0.0.3576 (the addresses named below are 2976's; 3527's and 3576's tables are at
// the end of the file).
//
// The game (gimmicks-dueno.md sections 1-2):
//   - the server writes a gimmick's controller once, at its creation (0x2791CD0, 0x2792A7B): in the host's field
//     the field owner, also for the "Game Mechanic" gimmicks docked to user 2's character (its grappling device);
//   - the 2005 carries it (record +0x12) into the client's actor +0x90; a client asks for / applies a gimmick event
//     only when [[local player+0xA0]+0x60] == [gimmick+0x90] (0x8E59D0, 0x8E5F60, 0x9065A0; refusal
//     eErrNoActorNotExist 0xD65F8D70), so the guest's client never runs its own device and its rope is not drawn.
//
// [session2] docked_gimmicks = 0 | probe | 1 (both PCs):
//   phase 1 ("local drive", mode 1, the GUEST's delivery): a type-7 record docked to THIS client's own character
//   (the parent key at name end +0xAC and +0xC6, both copies equal) whose controller is not this client's user gets
//   this client's user written at +0x12 before the game reads the 2005, so its client runs the device's state
//   machine for its own screen. The server keeps the host as the controller (nothing of the server changes): this
//   client's state requests for those keys are WITHHELD (never sent), so the server never sees two controllers.
//   Anything that does not pass every check goes through unchanged and is counted.
//   probe: the same decisions computed and counted ("would rewrite", "would withhold"); nothing changed.
//
// [session2] docked_gimmicks_other = 0 | probe | 1 (GUEST only; needs docked_gimmicks probe or 1; the host ignores
// it): the mirror for the OTHER player's character (P8 session 29, gimmicks-dueno.md section 8). S28 showed the
// guest's client never runs the host's grappling device either (controller 0x90100000, 0 state requests from the
// guest for it), so the host's rope is not drawn on the guest; the host's client, controller of BOTH devices, drives
// the guest's from the guest character's replicated actions (78 / 78 events matched in time). Mode 1: the same
// rewrite (+0x12 = this client's user, "Game Mechanic", a user controller, packet well formed) for a type-7 record
// docked to ANOTHER player character key (0xA...); the key joins the local-only set (with its parent and an "other"
// flag), so its listed state requests are withheld too. probe: "would rewrite (other player)", nothing written.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>

namespace cdmp::session2::dgl {

// ---------------------------------------------------------------- the key

enum class Mode : uint8_t { Off, Probe, On };
struct ParsedMode {
    Mode mode = Mode::Off;
    bool ok = true;  // false: an unknown value (treated as off)
};
inline ParsedMode parse_mode(std::string_view raw) {
    while (!raw.empty() && (raw.front() == ' ' || raw.front() == '\t')) raw.remove_prefix(1);
    if (const size_t c = raw.find_first_of(";#"); c != std::string_view::npos) raw = raw.substr(0, c);
    while (!raw.empty() && (raw.back() == ' ' || raw.back() == '\t' || raw.back() == '\r' || raw.back() == '\n')) {
        raw.remove_suffix(1);
    }
    std::string v(raw);
    for (char& ch : v) ch = static_cast<char>(ch >= 'A' && ch <= 'Z' ? ch - 'A' + 'a' : ch);
    if (v.empty() || v == "0" || v == "off" || v == "no" || v == "false") return {Mode::Off, true};
    if (v == "probe") return {Mode::Probe, true};
    if (v == "1" || v == "on" || v == "yes" || v == "true") return {Mode::On, true};
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

// ---------------------------------------------------------------- packets

inline constexpr size_t kHeader = 5;  // u16 opcode | u8 slot | u16 payload length
inline constexpr uint16_t kOpActorLoad = 2005;           // ActorLoadDataAck: [u16 len][record] ...
inline constexpr uint16_t kOpMainPlayerDataStart = 2756;  // u32 at +0: this client's own character
inline constexpr uint16_t kOpSceneUnspawnReq = 2221;     // SceneLevelOnDemandGimmickUnspawnReq: u8 4 | u32 n | n keys
inline constexpr uint16_t kOpSceneSpawnReq = 2928;       // SceneLevelOnDemandGimmickSpawnReq
// The state requests keyed by the gimmick at +0 that the guest withholds for its local-only keys
// (gimmicks-dueno.md section 6.1, from the server's handlers in build 2976):
//   3082 GimmickExecuteFrameEventReq   0x2AC1270: ignored unless the requester controls the gimmick
//   2758 UpdateGimmickReq              0x2AC0790: eErrNoActorNotExist unless the requester controls it
//   2609 GimmickBranchStateReq         0x29E0610: the server applies nothing
//   2774 UpdateGimmickBodyMotionTypeReq 0x29E5050: ACCEPTED from anyone (writes the component's +0x42D)
//   3089 UpdateGimmickConstraintDataReq 0x29E1E00 -> 0x2A987C0: no controller check found (accepted)
//   2779 CreateProjectileFromGimmickEventReq 0x2A3E370: no controller check found (would create a projectile)
//   2826 GimmickCatcherUpdateReq       0x29E47E0: not decoded (withheld to be safe)
//   2618 GamePlayTriggerInfoEnterReq   not decoded; the host's client sends it for the device (36 in H27-2): withheld
//                                      so that it keeps coming from the controller only
// So for 3082 / 2758 / 2609 withholding changes nothing on the server; for 2774 / 3089 / 2779 / 2826 / 2618 it keeps the
// host (the controller) the only writer.
inline constexpr uint16_t kWithheldOps[] = {3082, 2758, 2609, 2774, 3089, 2779, 2826, 2618};
inline constexpr size_t kWithheldOpCount = sizeof(kWithheldOps) / sizeof(kWithheldOps[0]);
inline int withheld_op_index(uint16_t op) {
    for (size_t i = 0; i < kWithheldOpCount; ++i) {
        if (kWithheldOps[i] == op) return static_cast<int>(i);
    }
    return -1;
}

// A 2005 record (S27 captures, gimmicks-dueno.md section 1): +0 u8 type (0 user, 1 player character, 3-6 NPC /
// animal / mount, 7 gimmick), +1 the key, +5 the owner user, +0x12 the CONTROLLER (the server's actor +0x90),
// +0x1E u32 the name's length n (UTF-16), +0x22 the name. A gimmick docked to an actor carries the parent's key at
// name end +0xAC and +0xC6 (ne = 0x22 + 2n; "Game Mechanic", n = 13: +0xE8 / +0x102), the two copies equal.
inline constexpr size_t kRecType = 0x00;
inline constexpr size_t kRecKey = 0x01;
inline constexpr size_t kRecOwner = 0x05;
inline constexpr size_t kRecController = 0x12;
inline constexpr size_t kRecNameLen = 0x1E;
inline constexpr size_t kRecName = 0x22;
inline constexpr size_t kParentA = 0xAC;  // after the name
inline constexpr size_t kParentB = 0xC6;
// Where the parent's two copies sit after the name, per build. 2976 above. 3527 [V real 2005s of
// cdmp_packets.{host_20261105-070654,guest_20261105-070716}.bin, tail searched byte by byte for the player keys]: +0xB9
// and +0xD7, equal in all 24 + 24 records docked to a player (0xA0100001 / 0xA0100066, 8 per spawn of the character); the
// rest of the record's head (+0, +1, +5, +0x12, +0x1E, +0x22) is unchanged, and +0x12 still holds the field owner
// (0x90100000) for the devices docked to the guest's character in the host's field.
struct RecLayout {
    size_t parent_a, parent_b;
};
inline constexpr RecLayout kRecLayout2976{kParentA, kParentB};
inline constexpr RecLayout kRecLayout3527{0xB9, 0xD7};
inline constexpr uint32_t kMaxNameChars = 64;
inline constexpr uint8_t kTypePlayer = 1;
inline constexpr uint8_t kTypeGimmick = 7;

inline uint32_t le32(const uint8_t* p) {
    uint32_t v = 0;
    std::memcpy(&v, p, 4);
    return v;
}
inline void put32(uint8_t* p, uint32_t v) { std::memcpy(p, &v, 4); }
inline uint16_t le16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }

inline bool player_key(uint32_t k) { return (k >> 28) == 0xA; }
inline bool world_key(uint32_t k) { return (k >> 28) == 0xB; }
inline bool user_key(uint32_t k) { return (k >> 28) == 0x9; }

// The docked parent of a gimmick record: 0 when not a gimmick, not docked, short, or the two copies differ.
inline uint32_t docked_parent(std::span<const uint8_t> rec, const RecLayout& layout = kRecLayout2976) {
    if (rec.size() < kRecName || rec[kRecType] != kTypeGimmick) return 0;
    const uint32_t n = le32(&rec[kRecNameLen]);
    if (n == 0 || n >= kMaxNameChars) return 0;
    const size_t ne = kRecName + 2 * static_cast<size_t>(n);
    if (rec.size() < ne + layout.parent_b + 4) return 0;
    const uint32_t a = le32(&rec[ne + layout.parent_a]);
    const uint32_t b = le32(&rec[ne + layout.parent_b]);
    return a == b ? a : 0;
}

// The 2005 payload's records, in order: f(offset of the record in the payload, record bytes). False when the
// lengths do not add up (what came before is still visited; nothing after).
template <class F>
bool for_each_record(std::span<const uint8_t> pl, F&& f) {
    size_t o = 0;
    while (o + 2 <= pl.size()) {
        const size_t len = le16(&pl[o]);
        if (len < kRecKey + 4 || o + 2 + len > pl.size()) return false;
        f(o + 2, pl.subspan(o + 2, len));
        o += 2 + len;
    }
    return o == pl.size();
}

// ---------------------------------------------------------------- the local-only keys (phase 1)

// Gimmick keys this client drives locally (mode 1) or would (probe): written by the delivery (the client's
// NetworkThread), read by the send path (normally the same thread; any thread is safe). Fixed size; a full table
// overwrites the oldest entry (keys of an earlier spawn of the character, gone by then).
template <size_t N>
class KeySet {
public:
    bool contains(uint32_t k) const {
        if (k == 0) return false;
        for (const auto& e : e_) {
            if (e.load(std::memory_order_relaxed) == k) return true;
        }
        return false;
    }
    // True when newly added.
    bool add(uint32_t k) {
        if (k == 0 || contains(k)) return false;
        const uint32_t i = next_.fetch_add(1, std::memory_order_relaxed) % N;
        if (e_[i].load(std::memory_order_relaxed) != 0) overwritten_.fetch_add(1, std::memory_order_relaxed);
        e_[i].store(k, std::memory_order_relaxed);
        return true;
    }
    // True when it was there (every copy cleared).
    bool remove(uint32_t k) {
        if (k == 0) return false;
        bool found = false;
        for (auto& e : e_) {
            uint32_t cur = k;
            if (e.compare_exchange_strong(cur, 0, std::memory_order_relaxed)) found = true;
        }
        if (found) removed_.fetch_add(1, std::memory_order_relaxed);
        return found;
    }
    void clear() {
        for (auto& e : e_) e.store(0, std::memory_order_relaxed);
        next_.store(0, std::memory_order_relaxed);
    }
    size_t used() const {
        size_t n = 0;
        for (const auto& e : e_) n += e.load(std::memory_order_relaxed) != 0;
        return n;
    }
    uint64_t overwritten() const { return overwritten_.load(std::memory_order_relaxed); }
    uint64_t removed() const { return removed_.load(std::memory_order_relaxed); }
    static constexpr size_t capacity() { return N; }

private:
    std::atomic<uint32_t> e_[N] = {};
    std::atomic<uint32_t> next_{0};
    std::atomic<uint64_t> overwritten_{0}, removed_{0};
};
// The local-only keys (phase 1 and docked_gimmicks_other): each with the docked parent its 2005 named and flags
// (kKeyOn: mode 1, the client really drives it and its requests are WITHHELD; without it: probe, only counted as
// "would withhold"; kKeyOther: docked to the other player's character). Written by the delivery thread, read by the
// send path (any thread): a reader can see a key with the previous entry's parent / flags for an instant (benign: the
// same decision class). A key leaves when a 2005 names another parent or none, on a 2516, or on clear() (every world
// change). Full: the oldest entry is overwritten.
inline constexpr uint8_t kKeyOn = 1;
inline constexpr uint8_t kKeyOther = 2;
struct LocalKey {
    uint32_t parent = 0;
    uint8_t flags = 0;
};
template <size_t N>
class LocalKeySet {
public:
    bool contains(uint32_t k) const { return index_of(k) < N; }
    // The entry of k (nullopt-like: found = false).
    bool find(uint32_t k, LocalKey& out) const {
        const size_t i = index_of(k);
        if (i >= N) return false;
        out.parent = parent_[i].load(std::memory_order_relaxed);
        out.flags = flags_[i].load(std::memory_order_relaxed);
        return true;
    }
    // True when newly added (an existing key gets the new parent and flags).
    bool add(uint32_t k, uint32_t parent = 0, uint8_t flags = kKeyOn) {
        if (k == 0) return false;
        if (const size_t i = index_of(k); i < N) {
            parent_[i].store(parent, std::memory_order_relaxed);
            flags_[i].store(flags, std::memory_order_relaxed);
            return false;
        }
        const uint32_t i = next_.fetch_add(1, std::memory_order_relaxed) % N;
        if (key_[i].load(std::memory_order_relaxed) != 0) overwritten_.fetch_add(1, std::memory_order_relaxed);
        key_[i].store(0, std::memory_order_relaxed);
        parent_[i].store(parent, std::memory_order_relaxed);
        flags_[i].store(flags, std::memory_order_relaxed);
        key_[i].store(k, std::memory_order_release);
        return true;
    }
    // True when it was there (every copy cleared).
    bool remove(uint32_t k) {
        if (k == 0) return false;
        bool found = false;
        for (auto& e : key_) {
            uint32_t cur = k;
            if (e.compare_exchange_strong(cur, 0, std::memory_order_relaxed)) found = true;
        }
        if (found) removed_.fetch_add(1, std::memory_order_relaxed);
        return found;
    }
    void clear() {
        for (auto& e : key_) e.store(0, std::memory_order_relaxed);
        next_.store(0, std::memory_order_relaxed);
    }
    size_t used() const {
        size_t n = 0;
        for (const auto& e : key_) n += e.load(std::memory_order_relaxed) != 0;
        return n;
    }
    // Entries with all of `flags` set.
    size_t used_with(uint8_t flags) const {
        size_t n = 0;
        for (size_t i = 0; i < N; ++i) {
            n += key_[i].load(std::memory_order_relaxed) != 0 &&
                 (flags_[i].load(std::memory_order_relaxed) & flags) == flags;
        }
        return n;
    }
    uint64_t overwritten() const { return overwritten_.load(std::memory_order_relaxed); }
    uint64_t removed() const { return removed_.load(std::memory_order_relaxed); }
    static constexpr size_t capacity() { return N; }

private:
    size_t index_of(uint32_t k) const {
        if (k == 0) return N;
        for (size_t i = 0; i < N; ++i) {
            if (key_[i].load(std::memory_order_acquire) == k) return i;
        }
        return N;
    }
    std::atomic<uint32_t> key_[N] = {};
    std::atomic<uint32_t> parent_[N] = {};
    std::atomic<uint8_t> flags_[N] = {};
    std::atomic<uint32_t> next_{0};
    std::atomic<uint64_t> overwritten_{0}, removed_{0};
};
using LocalKeys = LocalKeySet<128>;

// What this client knows about itself (the delivery's thread only): its own character (2756) and its user (the
// controller of its own character's type-1 record, which the server sets to the user that controls it).
struct Self {
    uint32_t own_key = 0;
    uint32_t own_user = 0;
};

// One gimmick record docked to a player character, for the log and the comp+0x2B4 check (fixed size).
enum class Action : uint8_t {
    Rewritten,       // mode 1: +0x12 = own user, key local-only
    WouldRewrite,    // probe: the same decision, nothing written
    AlreadyMine,     // controller is already this client's user (the host's own devices; the guest's own world)
    OwnUserUnknown,  // docked to the own character but the own user is not known yet: unchanged
    OtherPlayer,     // docked to another player's character: unchanged (phase 1 never takes it)
    OwnKeyUnknown,   // a player-docked record before this client knows its own character: unchanged
    NotUserController,  // docked to the own character but +0x12 is not a user key (0, an actor...): unchanged
    NotGameMechanic,    // docked to the own character but not a "Game Mechanic" record: unchanged (logged only)
    MalformedPacket     // mode 1 would rewrite, but the packet's record lengths do not add up: unchanged
};
inline const char* action_name(Action a) {
    switch (a) {
        case Action::Rewritten: return "REWRITTEN (local drive)";
        case Action::WouldRewrite: return "would rewrite (probe)";
        case Action::AlreadyMine: return "already this client's";
        case Action::OwnUserUnknown: return "own user unknown: unchanged";
        case Action::OtherPlayer: return "another player's: unchanged";
        case Action::OwnKeyUnknown: return "own character unknown: unchanged";
        case Action::NotUserController: return "not rewritten (controller is not a user)";
        case Action::NotGameMechanic: return "not rewritten (name)";
        case Action::MalformedPacket: return "not rewritten (malformed packet)";
    }
    return "?";
}
inline constexpr size_t kNameChars = 24;
struct Docked {
    uint32_t key = 0;
    uint32_t parent = 0;
    uint32_t controller = 0;  // as received
    uint32_t written = 0;     // the value now at +0x12 (== controller unless rewritten)
    Action action = Action::OtherPlayer;
    bool other = false;  // docked to the other player's character and decided by docked_gimmicks_other (probe / 1)
    char name[kNameChars] = {};  // the record's name, ASCII ('?' for anything else), cut to kNameChars - 1
};
// The log text of a decision, with the docked_gimmicks_other ones marked.
inline const char* docked_action_name(const Docked& d) {
    if (!d.other) return action_name(d.action);
    switch (d.action) {
        case Action::Rewritten: return "REWRITTEN (other player, local drive)";
        case Action::WouldRewrite: return "would rewrite (other player, probe)";
        case Action::AlreadyMine: return "other player's, already this client's: unchanged";
        case Action::OwnUserUnknown: return "other player's, own user unknown: unchanged";
        case Action::NotUserController: return "other player's, not rewritten (controller is not a user)";
        case Action::NotGameMechanic: return "other player's, not rewritten (name)";
        case Action::MalformedPacket: return "other player's, not rewritten (malformed packet)";
        default: return action_name(d.action);
    }
}

// The name every S27 gimmick docked to a player character carried (25 / 23 records): the only one phase 1 rewrites.
inline constexpr char kGameMechanic[] = "Game Mechanic";
// The record's name (UTF-16 at +0x22, n at +0x1E) as ASCII into out (always terminated); false when unreadable.
inline bool record_name(std::span<const uint8_t> rec, char* out, size_t cap) {
    if (cap == 0) return false;
    out[0] = 0;
    if (rec.size() < kRecName) return false;
    const uint32_t n = le32(&rec[kRecNameLen]);
    if (n == 0 || n >= kMaxNameChars || rec.size() < kRecName + 2 * static_cast<size_t>(n)) return false;
    size_t k = 0;
    for (uint32_t i = 0; i < n && k + 1 < cap; ++i) {
        const uint16_t ch = le16(&rec[kRecName + 2 * static_cast<size_t>(i)]);
        out[k++] = (ch >= 0x20 && ch < 0x7F) ? static_cast<char>(ch) : '?';
    }
    out[k] = 0;
    return true;
}
inline bool is_game_mechanic(std::span<const uint8_t> rec) {
    if (rec.size() < kRecName) return false;
    const uint32_t n = le32(&rec[kRecNameLen]);
    constexpr size_t len = sizeof(kGameMechanic) - 1;
    if (n != len || rec.size() < kRecName + 2 * len) return false;
    for (size_t i = 0; i < len; ++i) {
        if (le16(&rec[kRecName + 2 * i]) != static_cast<uint8_t>(kGameMechanic[i])) return false;
    }
    return true;
}

struct Result2005 {
    uint32_t records = 0;
    uint32_t gimmicks = 0;
    uint32_t docked_world = 0;   // docked to an NPC / object (0xB key)
    uint32_t docked_player = 0;  // docked to a player character
    uint32_t not_docked = 0;
    uint32_t rewritten = 0;
    uint32_t would_rewrite = 0;
    uint32_t already_mine = 0;
    uint32_t own_user_unknown = 0;
    uint32_t own_key_unknown = 0;
    uint32_t other_player = 0;           // records docked to another player's character (all of them)
    uint32_t other_rewritten = 0;        // of them: docked_gimmicks_other = 1, rewritten
    uint32_t other_would_rewrite = 0;    // docked_gimmicks_other = probe
    uint32_t other_unchanged = 0;        // docked_gimmicks_other on, but a check failed (the reason in the line)
    uint32_t not_user_controller = 0;
    uint32_t not_game_mechanic = 0;
    uint32_t malformed_not_written = 0;
    uint32_t retired = 0;  // local-only keys dropped: announced again with another parent / not docked
    bool malformed = false;
    uint32_t learned_user = 0;  // the own user learned from this packet (0: none)
    static constexpr size_t kMaxDocked = 24;
    Docked docked[kMaxDocked];
    size_t docked_n = 0;          // entries kept
    uint32_t docked_not_kept = 0;  // player-docked records beyond kMaxDocked (counted only)
};

// The own user from the own character's type-1 record in a 2005 payload (its +0x12, a user key): written into
// self.own_user; returns it when it changed (0 otherwise). *ok: false when the record lengths do not add up.
inline uint32_t learn_own_user(std::span<const uint8_t> pl, Self& self, bool* ok = nullptr) {
    uint32_t learned = 0;
    const bool good = for_each_record(pl, [&](size_t, std::span<const uint8_t> rec) {
        if (rec.size() >= kRecController + 4 && rec[kRecType] == kTypePlayer && self.own_key &&
            le32(&rec[kRecKey]) == self.own_key) {
            const uint32_t ctl = le32(&rec[kRecController]);
            if (user_key(ctl) && ctl != self.own_user) {
                self.own_user = ctl;
                learned = ctl;
            }
        }
    });
    if (ok) *ok = good;
    return learned;
}

// The 2005 payload (header stripped) on its way into THIS client. Learns the own user from the own character's
// record; classifies every gimmick record; in mode On rewrites +0x12 of the "Game Mechanic" records docked to the own
// character whose controller is a user other than the own user, and adds them to `keys`. Nothing is written when the
// packet's record lengths do not add up (the whole packet passes untouched). Probe: the same decisions, nothing
// written, the keys added to `keys` all the same (so the send path can count what it would withhold). A local-only
// key announced again with another parent (or not docked) leaves `keys`. Off: nothing.
// `other` (docked_gimmicks_other; Off unless the caller is the guest): the same checks and rewrite for the records
// docked to ANOTHER player's character, their keys added with kKeyOther (and kKeyOn in mode 1).
// `layout`: where this build's records keep the parent (kRecLayout2976 / kRecLayout3527).
inline Result2005 process_2005(std::span<uint8_t> pl, Self& self, Mode mode, LocalKeys& keys, Mode other = Mode::Off,
                               const RecLayout& layout = kRecLayout2976) {
    Result2005 r;
    if (mode == Mode::Off) return r;
    // First the own character's record (its 2005 can share the packet with its devices).
    bool ok1 = true;
    r.learned_user = learn_own_user(pl, self, &ok1);
    r.malformed = !ok1;
    (void)for_each_record(pl, [&](size_t off, std::span<const uint8_t> rec) {
        ++r.records;
        if (rec[kRecType] != kTypeGimmick) return;
        ++r.gimmicks;
        const uint32_t parent = docked_parent(rec, layout);
        // A local-only key leaves when a 2005 names another parent than the one it was added with, or none.
        if (LocalKey lk; keys.find(le32(&rec[kRecKey]), lk) && (parent == 0 || parent != lk.parent)) {
            if (keys.remove(le32(&rec[kRecKey]))) ++r.retired;
        }
        if (parent == 0) {
            ++r.not_docked;
            return;
        }
        if (!player_key(parent)) {
            ++r.docked_world;
            return;
        }
        ++r.docked_player;
        if (rec.size() < kRecController + 4) return;  // cannot happen: docked_parent needs more
        Docked d;
        d.key = le32(&rec[kRecKey]);
        d.parent = parent;
        d.controller = le32(&rec[kRecController]);
        d.written = d.controller;
        (void)record_name(rec, d.name, kNameChars);
        if (self.own_key == 0) {
            d.action = Action::OwnKeyUnknown;
            ++r.own_key_unknown;
        } else if (parent != self.own_key) {
            ++r.other_player;
            d.action = Action::OtherPlayer;
            if (other != Mode::Off) {
                // docked_gimmicks_other: the mirror of phase 1 for the other player's character.
                d.other = true;
                if (self.own_user == 0) {
                    d.action = Action::OwnUserUnknown;
                } else if (d.controller == self.own_user) {
                    d.action = Action::AlreadyMine;
                } else if (!user_key(d.controller)) {
                    d.action = Action::NotUserController;
                } else if (!is_game_mechanic(rec)) {
                    d.action = Action::NotGameMechanic;
                } else if (other == Mode::On && r.malformed) {
                    d.action = Action::MalformedPacket;
                } else if (other == Mode::On) {
                    put32(pl.data() + off + kRecController, self.own_user);
                    d.written = self.own_user;
                    d.action = Action::Rewritten;
                    keys.add(d.key, parent, kKeyOn | kKeyOther);
                } else {
                    d.action = Action::WouldRewrite;
                    keys.add(d.key, parent, kKeyOther);
                }
                if (d.action == Action::Rewritten) {
                    ++r.other_rewritten;
                } else if (d.action == Action::WouldRewrite) {
                    ++r.other_would_rewrite;
                } else {
                    ++r.other_unchanged;
                }
            }
        } else if (self.own_user == 0) {
            d.action = Action::OwnUserUnknown;
            ++r.own_user_unknown;
        } else if (d.controller == self.own_user) {
            d.action = Action::AlreadyMine;
            ++r.already_mine;
        } else if (!user_key(d.controller)) {
            d.action = Action::NotUserController;
            ++r.not_user_controller;
        } else if (!is_game_mechanic(rec)) {
            d.action = Action::NotGameMechanic;
            ++r.not_game_mechanic;
        } else if (mode == Mode::On && r.malformed) {
            d.action = Action::MalformedPacket;
            ++r.malformed_not_written;
        } else if (mode == Mode::On) {
            put32(pl.data() + off + kRecController, self.own_user);
            d.written = self.own_user;
            d.action = Action::Rewritten;
            ++r.rewritten;
            keys.add(d.key, parent, kKeyOn);
        } else {
            d.action = Action::WouldRewrite;
            ++r.would_rewrite;
            keys.add(d.key, parent, 0);
        }
        if (r.docked_n < Result2005::kMaxDocked) {
            r.docked[r.docked_n++] = d;
        } else {
            ++r.docked_not_kept;
        }
    });
    return r;
}

// A whole troc packet (header + payload) into this client: the 2005 payload span, or empty.
inline std::span<uint8_t> payload_2005(std::span<uint8_t> packet) {
    if (packet.size() < kHeader || le16(packet.data()) != kOpActorLoad) return {};
    const size_t n = le16(packet.data() + 3);
    const size_t have = packet.size() - kHeader;
    return packet.subspan(kHeader, n < have ? n : have);
}

// A request this client is about to send (header + payload): the index in kWithheldOps when it is one of them and
// its gimmick (+0) is local-only, else -1. The caller withholds it only in mode On (probe counts it).
inline int withhold_index(std::span<const uint8_t> packet, const LocalKeys& keys) {
    if (packet.size() < kHeader + 4) return -1;
    const int i = withheld_op_index(le16(packet.data()));
    if (i < 0) return -1;
    return keys.contains(le32(packet.data() + kHeader)) ? i : -1;
}

// ---------------------------------------------------------------- probe tables (game threads, lock-free)

// Per gimmick key: the calls of the client's event request 0x8E59D0 (vf +0x740) and 0x8E5F60 that the probe saw,
// how many the game refused (eErrNoActorNotExist: not this client's to control), the event hashes and the docked
// player parent its 2005 named (P8 S29: S28 read the component's +0x2B4 here, which was 0 for every player-docked
// gimmick in 80 / 80 checks: not the parent). Insert by CAS on an empty key; full: counted only.
struct ClientEntry {
    std::atomic<uint32_t> key{0};
    std::atomic<uint32_t> parent{0xFFFFFFFFu};  // the 2005's player parent, 0 none (0xFFFFFFFF: not looked up yet)
    std::atomic<uint32_t> calls[2] = {};        // [0] 0x8E59D0, [1] 0x8E5F60
    std::atomic<uint32_t> refused[2] = {};
    std::atomic<uint32_t> first_hash{0}, last_hash{0}, last_refused_hash{0};
};
struct ServerEntry {
    std::atomic<uint32_t> key{0};
    std::atomic<uint32_t> accepted[2] = {};  // [0] 3082 ExecuteFrameEvent 0x2AC1270, [1] 2758 Update 0x2AC0790
    std::atomic<uint32_t> rejected[2] = {};
    std::atomic<uint32_t> last_requester{0}, last_controller{0}, last_hash{0};
};
// Per world gimmick key, the last time (ms, GetTickCount64) each user's client sent a keyed request for it
// (2556 / 2828 / 3067 / 2758 / 3082 / 2609 / 2774 / 3089 at +0): [0] the host's client, [1] user 2's. The server's
// receive thread only writes it.
struct TouchEntry {
    std::atomic<uint32_t> key{0};
    std::atomic<uint64_t> last_ms[2] = {};
};

// Open addressing with at most kMaxProbe slots looked at per key (the game threads call it): a key that finds no
// slot within them is counted in full() and not tracked.
inline constexpr size_t kMaxProbe = 64;
template <class E, size_t N>
class Table {
public:
    E* get(uint32_t key) {
        if (key == 0) return nullptr;
        size_t i = hash(key) & (N - 1);
        for (size_t n = 0; n < kProbe; ++n, i = (i + 1) & (N - 1)) {
            uint32_t k = e_[i].key.load(std::memory_order_acquire);
            if (k == key) return &e_[i];
            if (k == 0) {
                uint32_t expect = 0;
                if (e_[i].key.compare_exchange_strong(expect, key, std::memory_order_acq_rel)) {
                    used_.fetch_add(1, std::memory_order_relaxed);
                    return &e_[i];
                }
                if (expect == key) return &e_[i];
            }
        }
        full_.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }
    const E* find(uint32_t key) const {
        if (key == 0) return nullptr;
        size_t i = hash(key) & (N - 1);
        for (size_t n = 0; n < kProbe; ++n, i = (i + 1) & (N - 1)) {
            const uint32_t k = e_[i].key.load(std::memory_order_acquire);
            if (k == key) return &e_[i];
            if (k == 0) return nullptr;
        }
        return nullptr;
    }
    const E& at(size_t i) const { return e_[i]; }
    // Every key forgotten (a new conversation: keys are per world). Racy against get/find by design: a reader sees
    // an entry or an empty slot.
    void clear() {
        for (E& e : e_) e.key.store(0, std::memory_order_relaxed);
        used_.store(0, std::memory_order_relaxed);
    }
    static constexpr size_t size() { return N; }
    uint64_t used() const { return used_.load(std::memory_order_relaxed); }
    uint64_t full() const { return full_.load(std::memory_order_relaxed); }

private:
    static_assert(N >= 2 && (N & (N - 1)) == 0, "N must be a power of two");
    static constexpr size_t kProbe = N < kMaxProbe ? N : kMaxProbe;
    static size_t hash(uint32_t k) { return static_cast<size_t>((k * 2654435761u) >> 7); }
    E e_[N];
    std::atomic<uint64_t> used_{0}, full_{0};
};

// The class of a gimmick on this client, from the player parent its 2005 named (0: none; the client probe does not
// tell NPC-docked from world gimmicks since S29, so World reads "not docked to a player").
enum class Class : uint8_t { World, DockedNpc, DockedOwn, DockedOtherPlayer, Unknown, Count };
inline const char* class_name(Class c) {
    switch (c) {
        case Class::World: return "not docked to a player (world / NPC)";
        case Class::DockedNpc: return "docked to an NPC/object";
        case Class::DockedOwn: return "docked to THIS client's character";
        case Class::DockedOtherPlayer: return "docked to the other player's character";
        case Class::Unknown: return "parent unread";
        case Class::Count: break;
    }
    return "?";
}
// own_player(parent): whether a player key is this client's own character.
template <class OwnPlayer>
Class classify(uint32_t parent, OwnPlayer&& own_player) {
    if (parent == 0xFFFFFFFFu) return Class::Unknown;
    if (parent == 0) return Class::World;
    if (player_key(parent)) return own_player(parent) ? Class::DockedOwn : Class::DockedOtherPlayer;
    return Class::DockedNpc;
}

// The age of the other user's last request for a gimmick when one user asks to unspawn it (2221), in buckets:
// < 0.5 s, < 2 s, < 10 s, < 60 s, older, never. Measured only (section 3.6 of gimmicks-dueno.md).
inline constexpr size_t kAgeBuckets = 6;
inline size_t age_bucket(uint64_t now_ms, uint64_t last_ms) {
    if (last_ms == 0 || last_ms > now_ms) return 5;
    const uint64_t a = now_ms - last_ms;
    if (a < 500) return 0;
    if (a < 2000) return 1;
    if (a < 10000) return 2;
    if (a < 60000) return 3;
    return 4;
}
inline const char* age_bucket_name(size_t b) {
    static const char* const names[kAgeBuckets] = {"<0.5s", "<2s", "<10s", "<60s", "older", "never"};
    return b < kAgeBuckets ? names[b] : "?";
}
// The requests whose +0 key counts as "this user's client still has the gimmick" for the 2221 probe.
inline bool touch_op(uint16_t op) {
    switch (op) {
        case 2556: case 2828: case 3067: case 2758: case 3082: case 2609: case 2774: case 3089: return true;
        default: return false;
    }
}
// 2221: u8 4 | u32 n | n x u32 key. The keys present in `pl` (which may be cut: the caller reads a fixed prefix), at
// most max_keys; *total = n as the packet says (0 when the payload is not that).
inline size_t unspawn_keys(std::span<const uint8_t> pl, uint32_t* out, size_t max_keys, uint32_t* total = nullptr) {
    if (total) *total = 0;
    if (pl.size() < 5 || pl[0] != 4) return 0;
    const uint32_t n = le32(&pl[1]);
    if (n == 0 || n > 4096) return 0;
    if (total) *total = n;
    size_t k = 0;
    for (uint32_t i = 0; i < n && k < max_keys && 5 + (static_cast<size_t>(i) + 1) * 4 <= pl.size(); ++i) {
        out[k++] = le32(&pl[5 + static_cast<size_t>(i) * 4]);
    }
    return k;
}
// RemoveActorAck 2516: u8 4 | u32 | u8 reason | u32 key (+6), more keys after it in a longer one (S27: 10 bytes).
inline constexpr uint16_t kOpRemoveActor = 2516;
inline size_t removed_keys(std::span<const uint8_t> pl, uint32_t* out, size_t max_keys) {
    size_t k = 0;
    for (size_t i = 6; i + 4 <= pl.size() && k < max_keys; i += 4) out[k++] = le32(&pl[i]);
    return k;
}

// ---------------------------------------------------------------- build 1.0.0.2976: verified bytes

// Client: the gimmick event request (vf +0x740 of pa::ClientGimmickActorComponent, vtable 0x55B7898; also the
// UpdateGimmickAck 2297 handler's apply): (comp, int* err, event*, ?). Its control check at 0x8E5A41 / refusal
// 0x8E5A49. 5-byte patch = one whole instruction.
inline constexpr uintptr_t kClientRequest = 0x8E59D0;
inline constexpr uint8_t kClientRequestHead[21] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x4C, 0x89, 0x44, 0x24, 0x18, 0x55,
                                                   0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57};
// The second requester with the same check (callers 0x909DC0 = vf +0x7E0, 0x8EC720): (comp, int* err, event*, ?, u8).
inline constexpr uintptr_t kClientRequest2 = 0x8E5F60;
inline constexpr uint8_t kClientRequest2Head[20] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x4C, 0x89, 0x4C, 0x24, 0x20,
                                                    0x4C, 0x89, 0x44, 0x24, 0x18, 0x48, 0x89, 0x4C, 0x24, 0x08};
inline constexpr uintptr_t kClientGimmickVtbl = 0x55B7898;
inline constexpr uintptr_t kClientGimmickRequestSlot = 0x55B7898 + 0x740;  // holds 0x8E59D0
inline constexpr uint32_t kComp_Actor = 0x08;
// Not the docked parent (S28: 0 in 80 / 80 checks on both PCs, also for the natively controlled devices): logged by
// the 1.5 s check for information only, never compared.
inline constexpr uint32_t kComp_DockParent = 0x2B4;
inline constexpr uint32_t kActor_Comps = 0x68;
inline constexpr uint32_t kComps_Gimmick = 0x30;
inline constexpr uint32_t kActor_Key = 0x60;
inline constexpr uint32_t kActor_Controller = 0x90;
inline constexpr uint32_t kActor_Control = 0xC8;  // u8, 3 for every gimmick (0x4FA530)
inline constexpr uint32_t kActor_TypeInfo = 0x88;  // [+0x88]+1: the actor's type (7 = gimmick)
// eErrNoActorNotExist (hashlittle("eErrNoActorNotExist", 0xC5EDE)), the global the game registers at 0x21FC0F9.
inline constexpr uint32_t kErrNotController = 0xD65F8D70;
inline constexpr uintptr_t kErrNotControllerGlobal = 0x6CF6B68;

// Server (host): the equipment docking spawn 0x28AD170 (2249; caller 0x2970ADF) and the other docking spawn
// 0x28ADE40 (2973), both (docking component, int* err, request*); [component+8] = the docked-to actor.
inline constexpr uintptr_t kDockEquip = 0x28AD170;
inline constexpr uintptr_t kDockOther = 0x28ADE40;
inline constexpr uint8_t kDockHead[20] = {0x48, 0x89, 0x5C, 0x24, 0x18, 0x48, 0x89, 0x54, 0x24, 0x10,
                                          0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x56, 0x57, 0x41, 0x54};
inline constexpr uint8_t kDockEquipCall[5] = {0xE8, 0x8C, 0xC6, 0xF3, 0xFF};  // 0x2970ADF: call 0x28AD170
inline constexpr uintptr_t kDockEquipCallSite = 0x2970ADF;
// The controller's write in ICreateServerActorDesc::vf3 0x2791CD0: mov [r14+0x90],eax (one 7-byte instruction;
// r14 the new actor, r13 the field, eax the controller: the field owner [r13+0x180] unless the descriptor or an
// owner user said otherwise), then mov rax,[rsi] | mov r9,r14 | mov r8,r13 | lea rdx,[rbp+0x67].
inline constexpr uintptr_t kControllerWrite = 0x2792A7B;
inline constexpr uint8_t kControllerWriteBytes[20] = {0x41, 0x89, 0x86, 0x90, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x06,
                                                      0x4D, 0x8B, 0xCE, 0x4D, 0x8B, 0xC5, 0x48, 0x8D, 0x55, 0x67};
inline constexpr uint32_t kControllerWritePatch = 7;
// The block's head (unique in the exe, control-npc-lejos.md §1.1): mov eax,[r14+0x90] | test eax,eax | jne 0x2792A7B |
// mov rax,[rsi+0x40] | test.. : r14 = the actor, rsi = the descriptor (callee-saved across 0x389570 / 0x4A2010).
inline constexpr uintptr_t kControllerBlock = 0x2792A11;
inline constexpr uint8_t kControllerBlockBytes[16] = {0x41, 0x8B, 0x86, 0x90, 0x00, 0x00, 0x00, 0x85,
                                                      0xC0, 0x75, 0x5F, 0x48, 0x8B, 0x46, 0x40, 0x48};
// Its "from the field owner" read just before: mov eax,[r13+0x180] | test eax,eax | je 0x2792A82.
inline constexpr uintptr_t kFieldOwnerRead = 0x2792A70;
inline constexpr uint8_t kFieldOwnerReadBytes[11] = {0x41, 0x8B, 0x85, 0x80, 0x01, 0x00, 0x00, 0x85, 0xC0, 0x74, 0x07};
inline constexpr uint32_t kField_Owner = 0x180;
// The server's gimmick logic: ExecuteFrameEvent 0x2AC1270 (comp, requester user actor, event*, u16*), void; and
// Update 0x2AC0790 (comp, int* err, requester, data*). Both: accepted only when [[comp+8]+0x90] ==
// ([requester+0xA0] ? [[requester+0xA0]+0x60] : 0).
inline constexpr uintptr_t kServerExecute = 0x2AC1270;
inline constexpr uint8_t kServerExecuteHead[21] = {0x4C, 0x89, 0x4C, 0x24, 0x20, 0x4C, 0x89, 0x44, 0x24, 0x18, 0x48,
                                                   0x89, 0x4C, 0x24, 0x08, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54};
inline constexpr uintptr_t kServerUpdate = 0x2AC0790;
inline constexpr uint8_t kServerUpdateHead[21] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41,
                                                  0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24, 0xA0};
inline constexpr uint32_t kUser_Owner = 0xA0;  // the requester's +0xA0 -> its +0x60 = the user key
// The only patch size accepted at every entry: safetyhook's 5-byte jump over whole instructions (the 14-byte
// fallback is refused). Every head above begins with one 5-byte instruction.
inline constexpr uint32_t kEntryPatch = 5;

// ---------------------------------------------------------------- build 1.0.0.3527 [V capstone on the installed PE]

// Client. pa::ClientGimmickActorComponent 0x59459E0 (RTTI, 278 slots as in 2976). The request is the 2297 handler's
// (UpdateGimmickAck vtable 0x5997D38 slot 2 = 0xCD11F0, call at 0xCD1488), same 21-byte head as 2976 (kClientRequestHead),
// its control check 0x9D0641 cmp eax,[rsi+0x90], its refusal 0x9D0649. Its vtable slot moved to +0x748. The second
// requester has its own head (r9 saved before r8), the same check (0x9D0B6F, refusal 0x9D0B78) and 5 arguments (a u8 at
// [rbp+0x60]; callers 0x9D7F56, 0x9F6315). Both refuse with the global below (hashlittle eErrNoActorNotExist).
inline constexpr uintptr_t kClientRequest3527 = 0x9D05D0;
inline constexpr uintptr_t kClientRequest23527 = 0x9D0B00;
inline constexpr uint8_t kClientRequest2Head3527[20] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x4C, 0x89, 0x4C, 0x24, 0x20,
                                                        0x4C, 0x89, 0x44, 0x24, 0x18, 0x55, 0x56, 0x57, 0x41, 0x54};
// The two control compares (guest_gimmick_interact, gimmick_interact_logic.h; same on 3549, capstone 2026-11-06): eax =
// this client's user, the gimmick actor in rsi / r13 (= [comp+8]); both followed by je +0x6E to the accepted path, which
// overwrites rax at once (lea rax,[...]). A jmp lands on each compare (0x9D063D / 0x9D0B6B), at its first byte only.
inline constexpr uintptr_t kClientCheck3527 = 0x9D0641;   // cmp eax,[rsi+0x90] | je 0x9D06B7
inline constexpr uint8_t kClientCheckBytes3527[8] = {0x3B, 0x86, 0x90, 0x00, 0x00, 0x00, 0x74, 0x6E};
inline constexpr uint32_t kClientCheckPatch3527 = 6;
inline constexpr uintptr_t kClientCheck23527 = 0x9D0B6F;  // cmp eax,[r13+0x90] | je 0x9D0BE6
inline constexpr uint8_t kClientCheck2Bytes3527[9] = {0x41, 0x3B, 0x85, 0x90, 0x00, 0x00, 0x00, 0x74, 0x6E};
inline constexpr uint32_t kClientCheck2Patch3527 = 7;
inline constexpr uintptr_t kClientGimmickVtbl3527 = 0x59459E0;
inline constexpr uintptr_t kClientGimmickRequestSlot3527 = 0x59459E0 + 0x748;  // holds 0x9D05D0
inline constexpr uintptr_t kErrNotControllerGlobal3527 = 0x7148C80;
// Server (host). 2249 handler 0x2BE4700 (vtable 0x5EEC6D8 slot 2): rcx = [[actor+0x68]+0x170], 0x2BE4B34 call 0x2B0BF80.
// The other docking spawn: handler 0x2BE53E0 (TrocTrOnDemandDockingGimmickSpawnReq 0x5EEC698 slot 2), 0x2BE57EE call
// 0x2B0CC70. Both one caller, the same 20-byte head (kDockHead).
inline constexpr uintptr_t kDockEquip3527 = 0x2B0BF80;
inline constexpr uintptr_t kDockOther3527 = 0x2B0CC70;
inline constexpr uint8_t kDockEquipCall3527[5] = {0xE8, 0x47, 0x74, 0xF2, 0xFF};
inline constexpr uintptr_t kDockEquipCallSite3527 = 0x2BE4B34;
// The controller's write: the same 20 bytes (kControllerWriteBytes) once in the exe, inside [0x29CB290, 0x29CC624); same
// registers (r14 the actor, r13 the field, rsi the descriptor); no branch lands in 0x29CBF62..0x29CBF67. The block's head
// has another jne displacement; the field-owner read is the same 11 bytes (kFieldOwnerReadBytes).
inline constexpr uintptr_t kControllerWrite3527 = 0x29CBF61;
inline constexpr uintptr_t kControllerBlock3527 = 0x29CBEFC;
inline constexpr uint8_t kControllerBlockBytes3527[16] = {0x41, 0x8B, 0x86, 0x90, 0x00, 0x00, 0x00, 0x85,
                                                          0xC0, 0x75, 0x5A, 0x48, 0x8B, 0x46, 0x40, 0x48};
inline constexpr uintptr_t kFieldOwnerRead3527 = 0x29CBF56;
// The server's gimmick logic: 3082 handler 0x2C66A80 calls 0x2D52980 at 0x2C66D6F (same head, kServerExecuteHead; test
// 0x2D529CA cmp [r10+0x90],eax against [[rdx+0xA0]+0x60]); 2758 handler 0x2C64500 calls 0x2D51F10 at 0x2C64809 (own head;
// test 0x2D51F50, refusal 0x2D51F58).
inline constexpr uintptr_t kServerExecute3527 = 0x2D52980;
inline constexpr uintptr_t kServerUpdate3527 = 0x2D51F10;
inline constexpr uint8_t kServerUpdateHead3527[21] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x20, 0x55,
                                                      0x57, 0x41, 0x54, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C};

// ---------------------------------------------------------------- build 1.0.0.3576 (static, 2026-11-06; not yet run)

// Every function moved whole; the heads, compares, block and reads are 3527's bytes (kClientRequest2Head3527,
// kClientCheckBytes3527 / kClientCheck2Bytes3527 and their patches, kControllerBlockBytes3527, kServerUpdateHead3527).
// Client: pa::ClientGimmickActorComponent 0x5947AE0 (RTTI); its +0x748 holds the request 0x9D0820 (+0x250, kClientRequestHead).
// The second requester 0x9D0D50 (+0x250; its callers 0x9D81A6 / 0x9F6565 are 3527's + 0x250). The compares at the same
// +0x71 / +0x6F (0x9D0891 / 0x9D0DBF), each followed by je +0x6E; both refusals read the global 0x714ADA0
// (0x9D0899 / 0x9D0DC8).
inline constexpr uintptr_t kClientRequest3576 = 0x9D0820;
inline constexpr uintptr_t kClientRequest23576 = 0x9D0D50;
inline constexpr uintptr_t kClientCheck3576 = 0x9D0891;   // cmp eax,[rsi+0x90] | je 0x9D0907
inline constexpr uintptr_t kClientCheck23576 = 0x9D0DBF;  // cmp eax,[r13+0x90] | je 0x9D0E36
inline constexpr uintptr_t kClientGimmickVtbl3576 = 0x5947AE0;
inline constexpr uintptr_t kClientGimmickRequestSlot3576 = 0x5947AE0 + 0x748;  // holds 0x9D0820
inline constexpr uintptr_t kErrNotControllerGlobal3576 = 0x714ADA0;
// Server (host). The 2249 handler 0x2BE5370 (TrocTrOnDemandEquipDockingGimmickSpawnReq 0x5EEE518 slot 2) calls 0x2B0CBD0
// at 0x2BE57A4; TrocTrOnDemandDockingGimmickSpawnReq 0x5EEE4D8 slot 2 = 0x2BE6050 calls 0x2B0D8C0 at 0x2BE645E (the
// spawns +0xC50 with kDockHead, their only callers; the handlers +0xC70). The controller's write 0x29CCBB1
// (kControllerWriteBytes, still once in the exe) inside 0x29CBEE0 (3527's 0x29CB290 + 0xC50, the same 0x1394 bytes, the
// write at the same +0xCD1); the block 0x29CCB4C and the field-owner read 0x29CCBA6. The 3082 handler 0x2C676F0 calls
// 0x2D535F0 at 0x2C679DF; the 2758 handler 0x2C65170 calls 0x2D52B80 at 0x2C65479 (all +0xC70, the same heads).
inline constexpr uintptr_t kDockEquip3576 = 0x2B0CBD0;
inline constexpr uintptr_t kDockOther3576 = 0x2B0D8C0;
inline constexpr uint8_t kDockEquipCall3576[5] = {0xE8, 0x27, 0x74, 0xF2, 0xFF};
inline constexpr uintptr_t kDockEquipCallSite3576 = 0x2BE57A4;
inline constexpr uintptr_t kControllerWrite3576 = 0x29CCBB1;
inline constexpr uintptr_t kControllerBlock3576 = 0x29CCB4C;
inline constexpr uintptr_t kFieldOwnerRead3576 = 0x29CCBA6;
inline constexpr uintptr_t kServerExecute3576 = 0x2D535F0;
inline constexpr uintptr_t kServerUpdate3576 = 0x2D52B80;

// ---------------------------------------------------------------- build 1.0.0.3663 (static, 2026-11-13; never run)

// Client: pa::ClientGimmickActorComponent 0x59C3768 (RTTI, vtable_map_3576_3663.json); its +0x748 holds the request
// 0xA005C0 (kClientRequestHead identical). The second requester 0xA00AF0 (kClientRequest2Head3527 identical; callers
// 0xA07FA6 / 0xA26342). The compares at the same +0x71 / +0x6F (0xA00631 / 0xA00B5F; kClientCheckBytes3527 /
// kClientCheck2Bytes3527 identical, each followed by je +0x6E; the only branches to them land on their first byte,
// 0xA0062D / 0xA00B5B). Both refusals read the global 0x71CFB84 (0xA00639 / 0xA00B68), as does the server's Update
// refusal 0x2DB96E8 (327 RIP reads, an error-code global).
inline constexpr uintptr_t kClientRequest3663 = 0xA005C0;
inline constexpr uintptr_t kClientRequest23663 = 0xA00AF0;
inline constexpr uintptr_t kClientCheck3663 = 0xA00631;   // cmp eax,[rsi+0x90] | je 0xA006A7
inline constexpr uintptr_t kClientCheck23663 = 0xA00B5F;  // cmp eax,[r13+0x90] | je 0xA00BD6
inline constexpr uintptr_t kClientGimmickVtbl3663 = 0x59C3768;
inline constexpr uintptr_t kClientGimmickRequestSlot3663 = 0x59C3768 + 0x748;  // holds 0xA005C0
inline constexpr uintptr_t kErrNotControllerGlobal3663 = 0x71CFB84;
// Server (host). OnDemandEquipDockingGimmickSpawnReq 0x5F684D8 slot 2 = 0x2C4AE10 calls 0x2B70D60 at 0x2C4B244 (its only
// caller); OnDemandDockingGimmickSpawnReq 0x5F68518 slot 2 = 0x2C4BAF0 calls 0x2B71A80 at 0x2C4BEFE (its only caller);
// both spawns start with kDockHead. GimmickExecuteFrameEventReq 0x5F66718 slot 2 = 0x2CCE150 calls 0x2DBA110 at 0x2CCE43F
// (kServerExecuteHead; test 0x2DBA15A cmp [r10+0x90],eax against [[rdx+0xA0]+0x60]); UpdateGimmickReq 0x5F66998 slot 2 =
// 0x2CCBBD0 calls 0x2DB96A0 at 0x2CCBED9 (kServerUpdateHead3527; test 0x2DB96E0 against [[r8+0xA0]+0x60]).
// The controller's write CHANGED: in 0x2A2E6C0 (+0xD7B; 3576 +0xCD1) the field is in rdi, not r13: the field-owner
// read is `mov eax,[rdi+0x180] | test eax,eax | je +7` (0x2A2F431) and the write `mov [r14+0x90],eax` (0x2A2F43B, the
// same 7-byte instruction) is followed by mov rax,[rsi] | mov r9,r14 | mov r8,rdi | lea rdx,[rbp+0x60] (20 bytes, once in
// the code section); r14 the actor, rsi the descriptor as before; the block's head 0x2A2F3D2 (jne +0x5E). The only
// branch to the write lands on its first byte (0x2A2F3DB).
inline constexpr uintptr_t kDockEquip3663 = 0x2B70D60;
inline constexpr uintptr_t kDockOther3663 = 0x2B71A80;
inline constexpr uint8_t kDockEquipCall3663[5] = {0xE8, 0x17, 0x5B, 0xF2, 0xFF};
inline constexpr uintptr_t kDockEquipCallSite3663 = 0x2C4B244;
inline constexpr uintptr_t kControllerWrite3663 = 0x2A2F43B;
inline constexpr uint8_t kControllerWriteBytes3663[20] = {0x41, 0x89, 0x86, 0x90, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x06,
                                                          0x4D, 0x8B, 0xCE, 0x4C, 0x8B, 0xC7, 0x48, 0x8D, 0x55, 0x60};
inline constexpr uintptr_t kControllerBlock3663 = 0x2A2F3D2;
inline constexpr uint8_t kControllerBlockBytes3663[16] = {0x41, 0x8B, 0x86, 0x90, 0x00, 0x00, 0x00, 0x85,
                                                          0xC0, 0x75, 0x5E, 0x48, 0x8B, 0x46, 0x40, 0x48};
inline constexpr uintptr_t kFieldOwnerRead3663 = 0x2A2F431;
inline constexpr uint8_t kFieldOwnerReadBytes3663[10] = {0x8B, 0x87, 0x80, 0x01, 0x00, 0x00, 0x85, 0xC0, 0x74, 0x07};
inline constexpr uintptr_t kServerExecute3663 = 0x2DBA110;
inline constexpr uintptr_t kServerUpdate3663 = 0x2DB96A0;

}  // namespace cdmp::session2::dgl
