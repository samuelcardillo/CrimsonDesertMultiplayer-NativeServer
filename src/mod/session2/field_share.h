#pragma once
// Option D, E3b (docs/research/opcion-d-campo-compartido.md): user 2 enters
// the host's ServerField instead of getting one of its own. The ServerField
// is built for several users (the list at +0x2A0, ToField, closing when every
// user actor has left), but ServerField::AddActor (.xtls) refuses a second
// user, and FieldManager::AcquireField always takes a new field from the pool.
// Two hooks on .rsrc function ENTRIES, only for user 2's character:
//
//   H1 FieldManager::AcquireField 0x2B07790: when user 2 travels to the level
//      of the host's open field, hand it the host's field (as the function
//      itself does at 0x2B079D5..0x2B07A47, but "not newly created": +0x20 = 0,
//      or a failure later would close the host's field).
//   H2 FieldMover::EnterField 0x2BC04F0: before the original, put {user 2, 0}
//      into the field's user list under the field's two locks, so AddActor
//      finds the user and skips the one-user cap; taken out again if the
//      original fails and the entry is still unused.
//
// Everything else stays native: AddActor/RemoveActor count the user's actors,
// the field closes only when every user actor has left.

#include <cstdint>
#include <string>

#include "mod/game/build_profile.h"

namespace cdmp::session2 {

// The game functions the hooks call (injectable for the tests).
struct FieldGame {
    bool(__fastcall* try_add_ref)(void* field);                 // 0x14343A0 (al = taken)
    void(__fastcall* vec_push)(void* vec, const void* entry);  // 0x40B5B0, 16-byte entries
};

// An entry of field+0x2A0 (AddActor: {user, 1} at [rsp+0x20], 0x1064C852).
struct FieldUserEntry {
    uint64_t user;
    uint32_t actors;
    uint32_t pad;
};

// ServerField and FieldMover offsets (build 1.0.0.2976).
namespace fld {
inline constexpr uint32_t kRefs = 0x10;          // u32 strong references
inline constexpr uint32_t kLock1 = 0x18;         // lock object (vtable: +8 lock, +0x10 unlock)
inline constexpr uint32_t kLock2Ptr = 0x08;      // -> lock object
inline constexpr uint32_t kOpen = 0x4A;          // u8 open
inline constexpr uint32_t kOwner = 0x180;        // u32 owner user key
inline constexpr uint32_t kUsers = 0x2A0;        // FieldUserEntry*
inline constexpr uint32_t kUserCount = 0x2A8;    // u32
inline constexpr uint32_t kUserActors = 0x2B0;   // u32
inline constexpr uint32_t kKey = 0x2C8;          // u32 field key (index, pool, generation)
inline constexpr uint32_t kLevelEntry = 0x2D0;   // -> level entry; u16 static level index at +4
// FieldMover (FM) = TransformSync + 0x4F0.
inline constexpr uint32_t kTsFieldMover = 0x4F0;
inline constexpr uint32_t kFmFieldKey = 0x08;    // u32 copy of field+0x2C8
inline constexpr uint32_t kFmField = 0x10;       // ServerField*
inline constexpr uint32_t kFmBusy = 0x5A;        // u16 accesses in progress
// FieldAttacher (AcquireField's `out`, 0x28 bytes, vtable: +0x10 release):
// written at 0x2B07A19 (+0x18), 0x2B07A1D (+8), 0x2B07A21 (+0x10), 0x2B07A35 (+0x20).
inline constexpr uint32_t kOutField = 0x08;
inline constexpr uint32_t kOutValid = 0x10;      // u8
inline constexpr uint32_t kOutHolder = 0x18;
inline constexpr uint32_t kOutNew = 0x20;        // u8 "newly created": 1 closes the field on failure (0x2BC006A)
inline constexpr uint32_t kOutInfoKey = 0x24;    // u32 FieldInfoKey of the destination (0x2B077C2)
// FieldManager's FieldInfoKey hash (0x2B077BC..0x2B07840): buckets of 0x100
// bytes at [+0x58], bucket = key % [+0x48]; a bucket is {u32 n; pad; n x {u32
// key, u32 index}}; [[+0x60] + index*8] = holder with +4 key and +8 level entry.
inline constexpr uint32_t kMgrBucketCount = 0x48;
inline constexpr uint32_t kMgrEntries = 0x4C;
inline constexpr uint32_t kMgrBuckets = 0x58;
inline constexpr uint32_t kMgrHolders = 0x60;
}  // namespace fld

// Build-selected offsets shared by field sharing, lifecycle probes, and the
// server diagnostics. Unknown/test executables intentionally use the legacy
// layout so the existing memory-backed unit tests keep their 1.0.0.2976
// fixtures; runtime hook installation still rejects unsupported builds.
struct RuntimeFieldLayout {
    uint32_t ts_field_mover;
    uint32_t users;
    uint32_t user_count;
    uint32_t user_actors;
    uint32_t key;
    uint32_t level_entry;
    uint32_t ts_sector;
    uint32_t fm_moving;
    uint32_t fm_busy;
    bool ts_moving_verified;
};

inline constexpr RuntimeFieldLayout kFieldLayout2976{fld::kTsFieldMover, fld::kUsers, fld::kUserCount,
                                                      fld::kUserActors, fld::kKey, fld::kLevelEntry,
                                                      0x540, 0x58, fld::kFmBusy, true};
// 3527 MoveField/AddActor paths prove the shifted FieldMover, ServerField
// tail, and sector pointer. Its GetField/release pair uses FM+48/+4A for
// move state/access count (old +58/+5A); MoveField still writes TS+3DC.
// Exact instructions: tools/porting/data/field_mover_layout_3527.json.
inline constexpr RuntimeFieldLayout kFieldLayout3527{0x508, 0x2A8, 0x2B0, 0x2B8, 0x2D0, 0x2D8,
                                                      0x548, 0x48, 0x4A, true};

// Build 1.0.0.3576 (static, 2026-11-06; not yet run) keeps 3527's layout: AddActor (.tls$ 0xE52BF90) reads
// +2A8/+2B0/+2B8/+2D8 and the FieldMover moves (0x2E61990 + 0xC70) use TS+0x508, FM+0x10/+0x40/+0x48/+0x4A with the
// same instruction bytes as field_mover_layout_3527.json.
// Build 1.0.0.3663 (static, 2026-11-13; never run) keeps it too: AddActor (protected 0xEB68740) reads
// +2A8/+2B0/+2B8/+2D8, MoveField 0x2ECA480 forms TS+0x508, and the FieldMover instructions of
// field_mover_layout_3527.json are found with 3527's bytes (+0x10/+0x40/+0x48/+0x4A); the TS sector +0x548 is read by
// ToNearExceptOne* vf1 (child_hold.cpp).
inline const RuntimeFieldLayout& runtime_field_layout() {
    const auto b = game::current_build();
    return b == game::Build::v3527 || b == game::Build::v3576 || b == game::Build::v3663 ? kFieldLayout3527
                                                                                          : kFieldLayout2976;
}

// The level entry AcquireField would use for this FieldInfoKey (its own
// lookup, read only); 0 if not found.
uintptr_t level_entry_for(uintptr_t manager, uint32_t info_key);

// The host's open field, if user 2 may share it now (H1's conditions 2-5 of
// opcion-d-campo-compartido.md §3.1): host_ts = the host character's
// TransformSync, level_entry = the level entry user 2 travels to (exactly the
// same entry as the host's field, not only the same level number). 0 = no
// (`why` says which check failed).
uintptr_t share_candidate(uintptr_t host_ts, uint32_t host_key, uintptr_t level_entry, std::string& why);

// H2's gate: the character entering (FM's [[FM]+8]) belongs to user2 and the
// field is not user 2's own. False for the host and for user 2's own field.
bool enter_is_shared(uintptr_t fm, uintptr_t field, uintptr_t user2);

// H1's action on AcquireField's `out` (0x2B079DD..0x2B07A47 with +0x20 = 0).
// False = nothing changed (the reference could not be taken).
bool share_give_field(const FieldGame& g, uintptr_t field, uintptr_t out, uint32_t* res);

// H2: {user, 0} into the field's list under its two locks, if not there.
// True = inserted (undo it with enter_undo if the enter fails).
bool enter_insert(const FieldGame& g, uintptr_t field, uintptr_t user);
// Takes user's entry out again if it is still at 0 actors.
void enter_undo(uintptr_t field, uintptr_t user);

// Install (hooks H2 then H1, after checking their first bytes); false = none.
bool field_share_install();
bool field_share_active();
std::string field_share_describe();

}  // namespace cdmp::session2
