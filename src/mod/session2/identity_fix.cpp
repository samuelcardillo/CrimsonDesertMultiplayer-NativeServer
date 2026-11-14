#include "mod/session2/identity_fix.h"

#include <windows.h>

#include <safetyhook.hpp>

#include <atomic>
#include <cstring>
#include <format>
#include <mutex>

#include "common/troc_frame.h"
#include "mod/game/build_profile.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/identity_probe.h"
#include "mod/session2/offsets_s2.h"
#include "mod/session2/profile_s2.h"
#include "mod/session2/server.h"

namespace cdmp::session2 {
namespace {

template <class T>
bool peek(uintptr_t a, T& v) {
    return a && game::safe_read(a, &v, sizeof v);
}

uintptr_t peekp(uintptr_t a) {
    uintptr_t v = 0;
    return peek(a, v) ? v : 0;
}

// One aligned 8-byte store (atomic on x64: a reader sees the old or the new
// number, never half of each). Kept free of C++ objects so __try is allowed.
bool guarded_store64(uintptr_t a, uint64_t v) {
    if (!a || (a & 7) != 0) return false;
    __try {
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(a), static_cast<LONG64>(v));
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

}  // namespace

// ------------------------------------------------------------------ pure logic

bool identity_number_allowed(uint64_t n) {
    return n != ~0ull && n != 0 && n != idf::kNative && n != idf::kOldPuppet;
}

const char* lobby_edit_name(LobbyEdit e) {
    switch (e) {
        case LobbyEdit::Write: return "written";
        case LobbyEdit::Already: return "already the assigned number";
        case LobbyEdit::Empty: return "no entry";
        case LobbyEdit::Ambiguous: return "ambiguous";
        case LobbyEdit::Unreadable: return "unreadable";
        case LobbyEdit::NotAllowed: return "number not allowed";
    }
    return "?";
}

LobbyPlan plan_lobby(std::span<const uint64_t> numbers, uint64_t assigned) {
    LobbyPlan p;
    p.count = static_cast<uint32_t>(numbers.size());
    if (!identity_number_allowed(assigned)) {
        p.what = LobbyEdit::NotAllowed;
        return p;
    }
    if (numbers.empty()) {
        p.what = LobbyEdit::Empty;
        return p;
    }
    uint32_t at_native = 0, at_assigned = 0;
    for (uint32_t i = 0; i < p.count; ++i) {
        if (numbers[i] == idf::kNative) {
            ++p.native;
            at_native = i;
        }
        if (numbers[i] == assigned) {
            ++p.assigned;
            at_assigned = i;
        }
    }
    if (p.native == 1 && p.assigned == 0) {
        p.what = LobbyEdit::Write;
        p.index = at_native;
    } else if (p.native == 0 && p.assigned == 1) {
        p.what = LobbyEdit::Already;
        p.index = at_assigned;
    } else {
        // Several entries with the constant, none, or the constant next to
        // the assigned number (writing would make a duplicate): never guess.
        p.what = LobbyEdit::Ambiguous;
    }
    return p;
}

std::optional<uint64_t> lobby_identity(std::span<const uint64_t> numbers, uint64_t assigned) {
    if (numbers.size() == 1) return numbers[0];
    const LobbyPlan p = plan_lobby(numbers, assigned);
    if (p.what == LobbyEdit::Already) return assigned;
    return std::nullopt;
}

bool read_lobby(uintptr_t comp, std::vector<uint64_t>& numbers, uintptr_t& data) {
    numbers.clear();
    data = 0;
    const uintptr_t list = peekp(comp + idf::kLobbyList);
    uint32_t count = 0;
    if (!comp || !list || !peek(list, data) || !peek(list + idf::kListCount, count)) return false;
    if (count > idf::kMaxEntries || (count && !data)) return false;
    numbers.resize(count);
    for (uint32_t i = 0; i < count; ++i) {
        if (!peek(data + static_cast<uintptr_t>(i) * idf::kEntryStride + idf::kEntryNumber, numbers[i])) {
            numbers.clear();
            return false;
        }
    }
    return true;
}

LobbyPlan lobby_normalise(uintptr_t comp, uint64_t assigned) {
    std::vector<uint64_t> numbers;
    uintptr_t data = 0;
    if (!read_lobby(comp, numbers, data)) return LobbyPlan{};  // Unreadable
    LobbyPlan p = plan_lobby(numbers, assigned);
    if (p.what != LobbyEdit::Write) return p;
    const uintptr_t at = data + static_cast<uintptr_t>(p.index) * idf::kEntryStride + idf::kEntryNumber;
    uint64_t back = 0;
    if (!guarded_store64(at, assigned) || !peek(at, back) || back != assigned) p.what = LobbyEdit::Unreadable;
    return p;
}

uintptr_t user_lobby(uintptr_t user) {
    const uintptr_t table = peekp(user + idf::kUserComponents);
    const uintptr_t comp = table ? peekp(table + idf::kTableLobby) : 0;
    return comp && user && peekp(comp + idf::kLobbyOwner) == user ? comp : 0;
}

const char* status_edit_name(StatusEdit e) {
    switch (e) {
        case StatusEdit::Written: return "written";
        case StatusEdit::Already: return "already the assigned number";
        case StatusEdit::NotNative: return "not the native constant";
        case StatusEdit::Unreadable: return "unreadable";
        case StatusEdit::NotAllowed: return "number not allowed";
    }
    return "?";
}

StatusEdit status_normalise_at(uintptr_t actor, uintptr_t status_vtable, uint64_t assigned, uint64_t& before,
                               uint32_t status_number_offset) {
    before = 0;
    if (!identity_number_allowed(assigned)) return StatusEdit::NotAllowed;
    if (status_number_offset != idf::kStatusNumber && status_number_offset != idf::kStatusNumber3527) {
        return StatusEdit::Unreadable;
    }
    const uintptr_t table = peekp(actor + idf::kUserComponents);
    const uintptr_t status = table ? peekp(table + idf::kTableStatus) : 0;
    if (!actor || !status || peekp(status + idf::kStatusActor) != actor) return StatusEdit::Unreadable;
    if (status_vtable && peekp(status) != status_vtable) return StatusEdit::Unreadable;
    // This is a POINTER to the u64. It is +0x70 in 2976 and +0x90 in 3527.
    const uintptr_t p = peekp(status + status_number_offset);
    if (!p || !peek(p, before)) return StatusEdit::Unreadable;
    if (before == assigned) return StatusEdit::Already;
    if (before != idf::kNative) return StatusEdit::NotNative;
    uint64_t back = 0;
    if (!guarded_store64(p, assigned) || !peek(p, back) || back != assigned) return StatusEdit::Unreadable;
    return StatusEdit::Written;
}

StatusEdit status_normalise(uintptr_t actor, uintptr_t status_vtable, uint64_t assigned, uint64_t& before) {
    return status_normalise_at(actor, status_vtable, assigned, before, identity_status_number_offset());
}

bool identity_invariant(std::optional<uint64_t> lobby, std::optional<uint64_t> status, uint64_t assigned,
                        std::string& why) {
    why.clear();
    if (!lobby) {
        why = "lobby unreadable or ambiguous";
    } else if (*lobby != assigned) {
        why = std::format("lobby 0x{:X}", *lobby);
    }
    if (!status) {
        why += why.empty() ? "" : ", ";
        why += "Status unreadable";
    } else if (*status != assigned) {
        why += why.empty() ? "" : ", ";
        why += std::format("Status 0x{:X}", *status);
    }
    if (!why.empty()) why += std::format(" (expected 0x{:X})", assigned);
    return why.empty();
}

std::optional<uint32_t> actors_with_number(uintptr_t data, uint32_t count, uint64_t number, uintptr_t except) {
    if (count > idf::kMaxActors || (count && !data)) return std::nullopt;
    std::vector<uintptr_t> actors(count);
    if (count && !game::safe_read(data, actors.data(), actors.size() * sizeof(uintptr_t))) return std::nullopt;
    uint32_t n = 0;
    for (const uintptr_t a : actors) {
        if (!a || a == except) continue;
        // [[a+0x68]+0x20] = Status (none: no number), then the build's number pointer.
        const uintptr_t table = peekp(a + idf::kUserComponents);
        const uintptr_t status = table ? peekp(table + idf::kTableStatus) : 0;
        const uintptr_t p = status ? peekp(status + identity_status_number_offset()) : 0;
        uint64_t v = 0;
        if (p && peek(p, v) && v == number) ++n;
    }
    return n;
}

// ------------------------------------------------------------------ the game side

namespace {

// Checked against the read-only copy of build 2976 with capstone (decoded on
// instruction boundaries). The lobby entry: no rel32 branch of
// .rsrc/.xtls/.text/.xtext lands in its first 0x20 bytes except a junk byte
// run at 0x20C24B4 (between int3 paddings, aiming at 0x2B7F4D4, the middle of
// the first instruction: not code).
constexpr uintptr_t kLobbyLoad = 0x2B7F4D0;  // (comp, int* res, -, data**) -> res; r8 unused, no stack args
constexpr uint8_t kLobbyLoadHead[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x56, 0x57,
                                      0x41, 0x54, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0xA0, 0x00, 0x00,
                                      0x00, 0x4C, 0x8B, 0xF2, 0x4C, 0x8B, 0xF9, 0x49, 0x8B, 0x39};
constexpr uintptr_t kLobbyVtable = 0x5B2BE58;     // ServerLobbyActorComponent; +0x50 = 0x2B7F4D0
constexpr uintptr_t kLobbyConstant = 0x2B7F66C;   // movabs rax,7FFF.. ; mov [rsp+0x70],rax
constexpr uint8_t kLobbyConstantBytes[] = {0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
                                           0x48, 0x89, 0x44, 0x24, 0x70};
constexpr uintptr_t kLobbyAddCall = 0x2B7F6DB;    // call 0x2143E70 (adds the entry, R8 = &number)
constexpr uint8_t kLobbyAddCallBytes[] = {0xE8, 0x90, 0x47, 0x5C, 0xFF};
// The 3093's ClearLobby: lobby = [[user+0x68]+0x10], owner [lobby+8], list [lobby+0x18].
constexpr uintptr_t kClearLobbySite = 0x2C3E0FF;
constexpr uint8_t kClearLobbySiteBytes[] = {0x49, 0x8B, 0x47, 0x68, 0x48, 0x8B, 0x58, 0x10, 0x48, 0x8B, 0x7B, 0x08};
constexpr uintptr_t kClearListSite = 0x2C3E126;
constexpr uint8_t kClearListSiteBytes[] = {0x48, 0x8B, 0x4B, 0x18};
constexpr uintptr_t kStatusVtable = 0x5B203F0;    // ServerStatusActorComponent; +0x50 = 0x293FE70
constexpr uintptr_t kStatusLoad = 0x293FE70;
// The logged-in actors that FindByCharacterNo 0x2A83F80 searches: manager =
// [[exe+0x6D696A8]] (0x2777A18), array [mgr+0xB8], u32 count [mgr+0xC0].
constexpr uintptr_t kLoginMgrSite = 0x2777A18;
constexpr uint8_t kLoginMgrSiteBytes[] = {0x48, 0x8B, 0x0D, 0x89, 0x1C, 0x5F, 0x04, 0x48, 0x8B, 0x09};
constexpr uintptr_t kLoginMgrSlot = 0x6D696A8;
constexpr uintptr_t kFindByNoScan = 0x2A84066;
constexpr uint8_t kFindByNoScanBytes[] = {0x48, 0x8B, 0x8D, 0xB8, 0x00, 0x00, 0x00, 0x8B, 0x85, 0xC0, 0x00, 0x00,
                                          0x00, 0x48, 0x8D, 0x14, 0xC1};
constexpr uintptr_t kFindByNoRead = 0x2A84090;
constexpr uint8_t kFindByNoReadBytes[] = {0x4C, 0x8B, 0x31, 0x49, 0x8B, 0x46, 0x68, 0x48, 0x8B, 0x40, 0x20};
// Build 1.0.0.3527. The entries come from named RTTI vtables; the inner
// checks retain the same constant/add-entry/3093-list semantics.
constexpr uintptr_t kLobbyLoad3527 = 0x2E1F600;
constexpr uint8_t kLobbyLoad3527Head[] = {
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x54, 0x24, 0x10, 0x55, 0x56, 0x57,
    0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0xF0,
    0xFD, 0xFF, 0xFF, 0x48, 0x81, 0xEC, 0x10, 0x03, 0x00, 0x00, 0x4C, 0x8B, 0xE2};
constexpr uintptr_t kLobbyVtable3527 = 0x5EF3450;
constexpr uintptr_t kLobbyConstant3527 = 0x2E1FA1B;
constexpr uint8_t kLobbyConstant3527Bytes[] = {
    0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x48, 0x89, 0x45, 0xC0};
constexpr uintptr_t kLobbyAddCall3527 = 0x2E1FA7B;
constexpr uint8_t kLobbyAddCall3527Bytes[] = {0xE8, 0xB0, 0xD6, 0x4E, 0xFF};
constexpr uintptr_t kClearLobbySite3527 = 0x2EE1E62;
constexpr uintptr_t kClearListSite3527 = 0x2EE1E89;
constexpr uintptr_t kStatusVtable3527 = 0x5EE7610;
constexpr uintptr_t kStatusLoad3527 = 0x2BAFA40;
// Build 1.0.0.3576 (static, 2026-11-06; not yet run). The lobby load and its two inner sites moved by +0xC70 with the
// 3527 bytes (LoadSaveData 0x2E1F600 -> 0x2E20270, constant 0x2E1FA1B -> 0x2E2068B); the add-entry call 0x2E1FA7B ->
// 0x2E206EB has a new rel32 (its target 0x230D130 -> 0x230DE80 is still the thunk of the .tls$ add-entry: the same
// [comp+0x18] list, stride 0xD0, number at +0, at 0xCB4B010). The 3093's sites 0x2EE1E62 / 0x2EE1E89 -> 0x2EE2AD2 /
// 0x2EE2AF9 (+0xC70, same bytes). Vtables by RTTI (vtable_map_3549_3576.json): lobby 0x5EF3450 -> 0x5EF5638 (slot
// +0x50 = 0x2E20270), Status 0x5EE7610 -> 0x5EE9828 (slot +0x50 = 0x2BB06B0, the old 0x2BAFA40 + 0xC70, a thunk
// whose .tls$ body 0xE390C80 still writes the constant through [Status+0x90] at 0xE390CCE). Server realm: TLS +0x1EB,
// set at 0x29ABB86 (3527 0x29AAF36 + 0xC50, same bytes).
constexpr uintptr_t kLobbyLoad3576 = 0x2E20270;
constexpr uintptr_t kLobbyVtable3576 = 0x5EF5638;
constexpr uintptr_t kLobbyConstant3576 = 0x2E2068B;
constexpr uintptr_t kLobbyAddCall3576 = 0x2E206EB;
constexpr uint8_t kLobbyAddCall3576Bytes[] = {0xE8, 0x90, 0xD7, 0x4E, 0xFF};  // 0x2E206EB: call 0x230DE80
constexpr uintptr_t kClearLobbySite3576 = 0x2EE2AD2;
constexpr uintptr_t kClearListSite3576 = 0x2EE2AF9;
constexpr uintptr_t kStatusVtable3576 = 0x5EE9828;
constexpr uintptr_t kStatusLoad3576 = 0x2BB06B0;
// Build 1.0.0.3663 (static, 2026-11-13; never run). Vtables by RTTI (vtable_map_3576_3663.json): lobby 0x5EF5638 ->
// 0x5F6F2E8, its slot +0x50 = LoadSaveData 0x2E879A0 (3527's 0x2E1F600 + 0x683A0; kLobbyLoad3527Head unchanged; .pdata
// to 0x2E87FF9). Inside, the function is 0xB bytes shorter before the constant: `movabs rax,7FFF.. ; mov [rbp-0x40],rax`
// (kLobbyConstant3527Bytes) at 0x2E87DB0 (+0x410, 3527 +0x41B) and the add-entry call at 0x2E87E10 (+0x470, 3527 +0x47B;
// r8 = &[rbp-0x40], new rel32) to the thunk 0x237EA60 (jmp 0xCF99D80 in the protected section: the same [comp+0x18]
// list, stride 0xD0, number at +0). The 3093's sites 0x2EE1E62 / 0x2EE1E89 -> 0x2F4AF52 / 0x2F4AF79 (+0x690F0, 3527's
// bytes; the first is unique near the shift). Status 0x5EE9828 -> 0x5F63430, slot +0x50 = 0x2C160B0, a thunk to the
// protected 0xE9F4150, which still writes the constant through [Status+0x90] at 0xE9F419E (identity_probe.cpp's +0x90
// on 3663). Server realm: TLS +0x1EB, set at 0x2A0E1B6 (3527 0x29AAF36 + 0x63280, same bytes).
constexpr uintptr_t kLobbyLoad3663 = 0x2E879A0;
constexpr uintptr_t kLobbyVtable3663 = 0x5F6F2E8;
constexpr uintptr_t kLobbyConstant3663 = 0x2E87DB0;
constexpr uintptr_t kLobbyAddCall3663 = 0x2E87E10;
constexpr uint8_t kLobbyAddCall3663Bytes[] = {0xE8, 0x4B, 0x6C, 0x4F, 0xFF};  // 0x2E87E10: call 0x237EA60
constexpr uintptr_t kClearLobbySite3663 = 0x2F4AF52;
constexpr uintptr_t kClearListSite3663 = 0x2F4AF79;
constexpr uintptr_t kStatusVtable3663 = 0x5F63430;
constexpr uintptr_t kStatusLoad3663 = 0x2C160B0;
constexpr uint32_t kLoginMgrActors = 0xB8;
constexpr uint32_t kLoginMgrCount = 0xC0;
constexpr uint16_t kOpLoginUser = 2490;
constexpr uint16_t kOpLoginCharacter = 3093;
constexpr uint64_t kMaxLogged = 48, kMaxRefusalsLogged = 8;

struct IdentityProfile {
    uintptr_t lobby_load, lobby_vtable, lobby_constant, lobby_add_call;
    uintptr_t clear_lobby, clear_list, status_vtable, status_load;
    uintptr_t login_mgr_site, login_mgr_slot, find_scan, find_read;
    const uint8_t* lobby_head; size_t lobby_head_size;
    const uint8_t* constant_bytes; size_t constant_size;
    const uint8_t* add_call_bytes; size_t add_call_size;
    uint32_t server_tls_flag;
};

const IdentityProfile* identity_profile() noexcept {
    static constexpr IdentityProfile old{
        kLobbyLoad, kLobbyVtable, kLobbyConstant, kLobbyAddCall, kClearLobbySite, kClearListSite,
        kStatusVtable, kStatusLoad, kLoginMgrSite, kLoginMgrSlot, kFindByNoScan, kFindByNoRead,
        kLobbyLoadHead, sizeof kLobbyLoadHead, kLobbyConstantBytes, sizeof kLobbyConstantBytes,
        kLobbyAddCallBytes, sizeof kLobbyAddCallBytes, 0x1EC};
    static constexpr IdentityProfile current{
        kLobbyLoad3527, kLobbyVtable3527, kLobbyConstant3527, kLobbyAddCall3527,
        kClearLobbySite3527, kClearListSite3527, kStatusVtable3527, kStatusLoad3527,
        0, 0, 0, 0, kLobbyLoad3527Head, sizeof kLobbyLoad3527Head,
        kLobbyConstant3527Bytes, sizeof kLobbyConstant3527Bytes,
        kLobbyAddCall3527Bytes, sizeof kLobbyAddCall3527Bytes, 0x1EB};
    static constexpr IdentityProfile current3576{
        kLobbyLoad3576, kLobbyVtable3576, kLobbyConstant3576, kLobbyAddCall3576,
        kClearLobbySite3576, kClearListSite3576, kStatusVtable3576, kStatusLoad3576,
        0, 0, 0, 0, kLobbyLoad3527Head, sizeof kLobbyLoad3527Head,
        kLobbyConstant3527Bytes, sizeof kLobbyConstant3527Bytes,
        kLobbyAddCall3576Bytes, sizeof kLobbyAddCall3576Bytes, 0x1EB};
    static constexpr IdentityProfile current3663{
        kLobbyLoad3663, kLobbyVtable3663, kLobbyConstant3663, kLobbyAddCall3663,
        kClearLobbySite3663, kClearListSite3663, kStatusVtable3663, kStatusLoad3663,
        0, 0, 0, 0, kLobbyLoad3527Head, sizeof kLobbyLoad3527Head,
        kLobbyConstant3527Bytes, sizeof kLobbyConstant3527Bytes,
        kLobbyAddCall3663Bytes, sizeof kLobbyAddCall3663Bytes, 0x1EB};
    switch (game::current_build()) {
        case game::Build::v2976: return &old;
        case game::Build::v3527: return &current;
        case game::Build::v3576: return &current3576;
        case game::Build::v3663: return &current3663;
        default: return nullptr;
    }
}

uintptr_t g_base = 0;
SafetyHookInline g_lobby;
std::atomic<bool> g_wanted{false}, g_active{false}, g_unique_on{false};
// User 2's identity (server thread writes, network thread reads).
std::atomic<uintptr_t> g_lobby_user{0};  // the user whose lobby holds the assigned number
std::atomic<uint32_t> g_lobby_epoch{0};
std::atomic<uint32_t> g_status_key{0};   // its login character, once normalised
std::atomic<bool> g_failed{false};
std::mutex g_fail_mu;
std::string g_fail_why;       // under g_fail_mu
bool g_logout_pending = false;  // under g_fail_mu
std::atomic<uint64_t> g_lobby_loads{0}, g_lobby_host{0}, g_lobby_written{0}, g_lobby_already{0}, g_lobby_bad{0},
    g_status_written{0}, g_status_already{0}, g_status_bad{0}, g_other_chars{0}, g_inv_ok{0}, g_inv_fail{0},
    g_refused{0}, g_clashes{0}, g_unchecked{0}, g_errors{0}, g_logged{0}, g_refusals_logged{0};

template <class... Args>
void note(std::format_string<Args...> fmt, Args&&... args) {
    if (g_logged.fetch_add(1) >= kMaxLogged) return;
    log::info("Session2 C2 identity: {}", std::format(fmt, std::forward<Args>(args)...));
}

uint32_t key_of(uintptr_t a) {
    uint32_t k = 0;
    return peek(a + idf::kActorKey, k) ? k : 0;
}

// Fail safe (identidad.md §5.2): log, refuse everything else of user 2 and
// ask the network thread for its native logout (identity_fix_take_logout).
void fail(const std::string& why) {
    g_failed.store(true);
    {
        std::lock_guard lock(g_fail_mu);
        if (g_fail_why.empty()) {
            g_fail_why = why;
            g_logout_pending = true;
        }
    }
    log::error("Session2 C2 identity: FAIL ({}); user 2 is logged out natively and nothing else of it reaches the "
               "server",
               why);
}

enum class Whose : uint8_t { Nobody, Host, User2, Stranger };

// owner = a ServerUserActor pointer (or 0). Stranger = a validated-looking
// user that is neither the host's nor session 2's (fail safe, as the clock gate).
Whose whose(uintptr_t owner, uintptr_t& user2) {
    user2 = 0;
    if (!owner) return Whose::Nobody;
    if (server_user2(user2) && owner == user2) return Whose::User2;
    uintptr_t host = 0;
    if (server_host_user(host) && owner == host) return Whose::Host;
    const uintptr_t user_vtable = profile::rva(off::kServerUserActorVtable);
    if (!user_vtable || peekp(owner) != g_base + user_vtable) return Whose::Nobody;
    return host ? Whose::Stranger : Whose::Nobody;  // host unknown: no guest can be in yet
}

// The server's realm, by the game's own TLS byte (+0x1EC of TLS block 0, set
// by ServerRunThread 0x27733A6). Not server_thread_id(): that is the thread
// that runs OnRecvPacket and built session 2, while the handlers and the loads
// run on another one (live C2 test 2026-10-09, lobby on T29232).
bool on_server_thread() {
    const uintptr_t tls_array = static_cast<uintptr_t>(__readgsqword(0x58));
    uintptr_t block = 0;
    uint8_t flag = 0;
    const auto* p = identity_profile();
    return p && game::safe_read(tls_array, &block, sizeof block) && block &&
           game::safe_read(block + p->server_tls_flag, &flag, sizeof flag) && flag != 0;
}

// Read only, unlocked (no game call may take the manager's lock): a stale
// entry only fails its safe reads. nullopt = not checked.
std::optional<uint32_t> number_in_use(uintptr_t except) {
    if (!g_unique_on.load()) return std::nullopt;
    const auto* p = identity_profile();
    if (!p || !p->login_mgr_slot) return std::nullopt;
    const uintptr_t holder = peekp(g_base + p->login_mgr_slot);
    const uintptr_t mgr = holder ? peekp(holder) : 0;
    uint32_t count = 0;
    if (!mgr || !peek(mgr + kLoginMgrCount, count)) return std::nullopt;
    return actors_with_number(peekp(mgr + kLoginMgrActors), count, idf::kUser2, except);
}

std::string unique_text(const std::optional<uint32_t>& n) {
    if (!n) return "not checked";
    return *n ? std::format("IN USE by {} actor(s)", *n) : std::string("unique");
}

// ---- lobby: ServerLobbyActorComponent::LoadSaveData, after the original

void on_lobby(uintptr_t comp, const int* r) {
    g_lobby_loads.fetch_add(1, std::memory_order_relaxed);
    int code = 0;
    if (!g_active.load() || !peek(reinterpret_cast<uintptr_t>(r), code) || code != 0) return;
    const auto* profile_cfg = identity_profile();
    if (!profile_cfg || peekp(comp) != g_base + profile_cfg->lobby_vtable) return;
    const uintptr_t owner = peekp(comp + idf::kLobbyOwner);
    uintptr_t user2 = 0;
    switch (whose(owner, user2)) {
        case Whose::Nobody:
            return;
        case Whose::Host:
            g_lobby_host.fetch_add(1, std::memory_order_relaxed);  // the host keeps the constant
            return;
        case Whose::Stranger:
            g_lobby_bad.fetch_add(1);
            fail(std::format("a lobby loads for user 0x{:08X}, neither the host's nor session 2's", key_of(owner)));
            return;
        case Whose::User2:
            break;
    }
    if (!on_server_thread()) {
        g_lobby_bad.fetch_add(1);
        fail("user 2's lobby loaded off the server thread");
        return;
    }
    // The engine adds the entry under the owner's lock ([owner+8], 0x393650) and
    // releases it before returning; every access to this list (add, clear,
    // 2869, the 3093 check) runs on this thread. Its count, for the log only.
    uint32_t lock_count = 0;
    const bool lock_ok = peek(peekp(owner + idf::kLockObject) + 8, lock_count);
    const std::optional<uint32_t> in_use = number_in_use(0);
    std::vector<uint64_t> before;
    uintptr_t data = 0;
    const bool read = read_lobby(comp, before, data);
    if (in_use && *in_use) {
        g_clashes.fetch_add(1);
        g_lobby_bad.fetch_add(1);
        g_lobby_user.store(0);
        fail(std::format("0x{:X} is already used by {} logged-in actor(s); user 2's lobby keeps the constant",
                         idf::kUser2, *in_use));
        return;
    }
    if (!in_use) g_unchecked.fetch_add(1);
    const LobbyPlan p = read ? lobby_normalise(comp, idf::kUser2) : LobbyPlan{};
    const uint32_t user_key = key_of(owner);
    if (p.what != LobbyEdit::Write && p.what != LobbyEdit::Already) {
        g_lobby_bad.fetch_add(1);
        g_lobby_user.store(0);
        fail(std::format("user 0x{:08X}'s lobby 0x{:X}: {} entries, {} with the constant, {} with 0x{:X}: {}",
                         user_key, comp, p.count, p.native, p.assigned, idf::kUser2, lobby_edit_name(p.what)));
        return;
    }
    (p.what == LobbyEdit::Write ? g_lobby_written : g_lobby_already).fetch_add(1);
    if (g_lobby_user.exchange(owner) != owner) g_status_key.store(0);  // a new user 2: its character is to come
    g_lobby_epoch.store(server_epoch());
    note("user 2 lobby 0x{:X} (user 0x{:08X}, epoch {}) entry {} of {}: 0x{:X} -> 0x{:X} ({}) | owner lock count {} "
         "| number {}",
         comp, user_key, server_epoch(), p.index + 1, p.count,
         p.index < before.size() ? before[p.index] : 0, idf::kUser2, lobby_edit_name(p.what),
         lock_ok ? std::format("{}", lock_count) : std::string("unreadable"), unique_text(in_use));
}

int* __fastcall lobby_detour(void* comp, int* res, void* r8, void* data) noexcept {
    int* r = g_lobby.unsafe_call<int*>(comp, res, r8, data);
    try {
        on_lobby(reinterpret_cast<uintptr_t>(comp), r);
    } catch (...) {
        g_errors.fetch_add(1);
    }
    return r;
}

// ---- Status: after LoadComponentsFromFile 0x20688A0 (identity_probe's hook)

void after_load(uintptr_t actor, const int* r) noexcept {
    try {
        int code = 0;
        if (!g_active.load(std::memory_order_relaxed) || !peek(reinterpret_cast<uintptr_t>(r), code) || code != 0) {
            return;
        }
        const uint32_t key = key_of(actor);
        if ((key >> 28) != idf::kCharacterClass) return;  // users (their lobby), children, NPCs
        const uintptr_t owner = peekp(actor + idf::kActorUser);
        uintptr_t user2 = 0;
        switch (whose(owner, user2)) {
            case Whose::Nobody:
            case Whose::Host:
                return;
            case Whose::Stranger:
                g_status_bad.fetch_add(1);
                fail(std::format("character 0x{:08X} of user 0x{:08X}, neither the host's nor session 2's, loads",
                                 key, key_of(owner)));
                return;
            case Whose::User2:
                break;
        }
        if (!on_server_thread()) {
            g_status_bad.fetch_add(1);
            fail(std::format("user 2's character 0x{:08X} loaded off the server thread", key));
            return;
        }
        if (g_lobby_user.load() != user2 || g_lobby_epoch.load() != server_epoch()) {
            g_status_bad.fetch_add(1);
            fail(std::format("user 2's character 0x{:08X} loads but its lobby does not hold 0x{:X}", key, idf::kUser2));
            return;
        }
        // One character per login gets the number: the game has other playable
        // characters a user can switch to (user's note of 10-09); a second one is
        // not the login's and is left as the game made it.
        const uint32_t prior = g_status_key.load();
        if (prior && prior != key) {
            g_other_chars.fetch_add(1);
            note("another character of user 2 loads (0x{:08X}; the login's is 0x{:08X}): left as it is", key, prior);
            return;
        }
        const std::optional<uint32_t> in_use = number_in_use(actor);
        if (in_use && *in_use) {
            g_clashes.fetch_add(1);
            g_status_bad.fetch_add(1);
            fail(std::format("0x{:X} is already used by {} other logged-in actor(s); user 2's character 0x{:08X} keeps "
                             "its number",
                             idf::kUser2, *in_use, key));
            return;
        }
        if (!in_use) g_unchecked.fetch_add(1);
        uint64_t before = 0;
        const auto* p = identity_profile();
        if (!p) return;
        const StatusEdit e = status_normalise(actor, g_base + p->status_vtable, idf::kUser2, before);
        if (e != StatusEdit::Written && e != StatusEdit::Already) {
            g_status_bad.fetch_add(1);
            fail(std::format("user 2's character 0x{:08X} Status: 0x{:X}, {}", key, before, status_edit_name(e)));
            return;
        }
        (e == StatusEdit::Written ? g_status_written : g_status_already).fetch_add(1);
        g_status_key.store(key);
        note("user 2 status of character 0x{:08X} (actor 0x{:X}): 0x{:X} -> 0x{:X} ({}) | number {}", key, actor,
             before, idf::kUser2, status_edit_name(e), unique_text(in_use));
    } catch (...) {
        g_errors.fetch_add(1);
    }
}

// ---- the invariant: entry of 0x2941020 (identity_probe's hook), obj = Status

void before_phases(uintptr_t obj) noexcept {
    try {
        if (!g_active.load(std::memory_order_relaxed)) return;
        const uintptr_t actor = peekp(obj + idf::kStatusActor);
        const uint32_t key = key_of(actor);
        if ((key >> 28) != idf::kCharacterClass) return;
        const uintptr_t owner = peekp(actor + idf::kActorUser);
        uintptr_t user2 = 0;
        switch (whose(owner, user2)) {
            case Whose::Nobody:
            case Whose::Host:
                return;
            case Whose::Stranger:
                g_inv_fail.fetch_add(1);
                fail(std::format("invariant FAIL: login phases of character 0x{:08X} of user 0x{:08X}, neither the "
                                 "host's nor session 2's",
                                 key, key_of(owner)));
                return;
            case Whose::User2:
                break;
        }
        std::vector<uint64_t> numbers;
        uintptr_t data = 0;
        std::optional<uint64_t> lobby;
        if (read_lobby(user_lobby(user2), numbers, data)) lobby = lobby_identity(numbers, idf::kUser2);
        std::optional<uint64_t> status;
        if (uint64_t no = 0; identity_character_no(actor, no)) status = no;
        std::string why;
        if (identity_invariant(lobby, status, idf::kUser2, why)) {
            g_inv_ok.fetch_add(1);
            note("invariant ok: user 2's character 0x{:08X} lobby = Status = 0x{:X} before its login phases", key,
                 idf::kUser2);
            return;
        }
        g_inv_fail.fetch_add(1);
        // The phases run natively (no invented error code); the logout follows.
        fail(std::format("invariant FAIL for user 2's character 0x{:08X}: {}", key, why));
    } catch (...) {
        g_errors.fetch_add(1);
    }
}

bool code_ok(uintptr_t rva, const uint8_t* bytes, size_t n, const char* what) {
    uint8_t actual[64] = {};
    if (n <= sizeof actual && game::safe_read(g_base + rva, actual, n) && std::memcmp(actual, bytes, n) == 0) {
        return true;
    }
    log::error("Session2 C2 identity: {} (exe+0x{:X}) is not the expected code", what, rva);
    return false;
}

}  // namespace

void identity_fix_set_wanted(bool wanted) { g_wanted.store(wanted); }
bool identity_fix_wanted() { return g_wanted.load(); }

bool identity_fix_install() {
    if (g_active.load()) return true;
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    const auto* p = identity_profile();
    if (!p) {
        log::error("Session2 C2 identity: unsupported game build");
        return false;
    }
    uintptr_t lobby_vf = 0, status_vf = 0;
    if (!code_ok(p->lobby_load, p->lobby_head, p->lobby_head_size, "ServerLobbyActorComponent::LoadSaveData") ||
        !code_ok(p->lobby_constant, p->constant_bytes, p->constant_size, "its constant") ||
        !code_ok(p->lobby_add_call, p->add_call_bytes, p->add_call_size, "its add-entry call") ||
        !code_ok(p->clear_lobby, kClearLobbySiteBytes, sizeof kClearLobbySiteBytes, "the 3093's lobby read") ||
        !code_ok(p->clear_list, kClearListSiteBytes, sizeof kClearListSiteBytes, "the 3093's lobby list read")) {
        return false;
    }
    if (!peek(g_base + p->lobby_vtable + 0x50, lobby_vf) || lobby_vf != g_base + p->lobby_load ||
        !peek(g_base + p->status_vtable + 0x50, status_vf) || status_vf != g_base + p->status_load) {
        log::error("Session2 C2 identity: the lobby / Status vtables are not the expected ones");
        return false;
    }
    // Uniqueness of the number among the logged-in actors: only if that list is where 0x2A83F80 reads it.
    g_unique_on.store(p->login_mgr_site && p->login_mgr_slot && p->find_scan && p->find_read &&
                      code_ok(p->login_mgr_site, kLoginMgrSiteBytes, sizeof kLoginMgrSiteBytes, "the login manager") &&
                      code_ok(p->find_scan, kFindByNoScanBytes, sizeof kFindByNoScanBytes, "its actor list") &&
                      code_ok(p->find_read, kFindByNoReadBytes, sizeof kFindByNoReadBytes, "its number read"));
    g_lobby = safetyhook::create_inline(reinterpret_cast<void*>(g_base + p->lobby_load),
                                        reinterpret_cast<void*>(&lobby_detour), SafetyHookInline::StartDisabled);
    if (!g_lobby) {
        log::error("Session2 C2 identity: cannot hook the lobby load");
        return false;
    }
    IdentityFixCalls calls;
    calls.after_load = &after_load;
    calls.before_phases = &before_phases;
    if (!identity_shared_hooks_install(calls)) {
        g_lobby = {};  // never enabled
        log::error("Session2 C2 identity: the shared component-load / Status login-phases hooks could not be "
                   "installed");
        return false;
    }
    if (!g_lobby.enable()) {
        g_lobby = {};
        log::error("Session2 C2 identity: cannot enable the lobby hook");
        return false;
    }
    g_active.store(true);
    log::info("Session2 C2 identity fix ON: user 2's characterNo = 0x{:X}, the host keeps 0x{:X} (lobby exe+0x{:X}, "
              "Status after the profiled component load, invariant at the profiled Status login phases); "
              "uniqueness check {}",
              idf::kUser2, idf::kNative, p->lobby_load, g_unique_on.load() ? "on" : "OFF (its code differs)");
    return true;
}

bool identity_fix_active() { return g_active.load(); }

bool identity_fix_admit(uint16_t opcode, std::span<const uint8_t> payload, std::string& why) {
    why.clear();
    if (!g_wanted.load() || opcode == troc::kOpLogoutSessionReq) return true;
    if (g_failed.load()) {
        std::lock_guard lock(g_fail_mu);
        why = "C2 identity failed: " + g_fail_why;
    } else if ((opcode == kOpLoginUser || opcode == kOpLoginCharacter) && !g_active.load()) {
        why = "the C2 identity fix is wanted (identity_fix=1) but not active";
    } else if (opcode == kOpLoginCharacter) {
        uintptr_t user2 = 0;
        uint64_t asked = 0;
        if (!server_user2(user2) || g_lobby_user.load() != user2 || g_lobby_epoch.load() != server_epoch()) {
            why = std::format("user 2's lobby does not hold 0x{:X}", idf::kUser2);
        } else if (payload.size() < 9) {
            why = "LoginCharacterToFieldServerReq too short";
        } else if (std::memcpy(&asked, payload.data() + 1, 8); asked != idf::kUser2) {
            why = std::format("LoginCharacterToFieldServerReq asks for characterNo 0x{:X}, user 2's is 0x{:X}", asked,
                              idf::kUser2);
        }
    }
    if (why.empty()) return true;
    g_refused.fetch_add(1);
    if (g_refusals_logged.fetch_add(1) < kMaxRefusalsLogged) {
        log::error("Session2 C2 identity: refused user 2's Req {}: {}", opcode, why);
    }
    return false;
}

bool identity_fix_take_logout(std::string& why) {
    if (!g_failed.load(std::memory_order_relaxed)) return false;
    std::lock_guard lock(g_fail_mu);
    if (!g_logout_pending) return false;
    g_logout_pending = false;
    why = "C2 identity: " + g_fail_why;
    return true;
}

void identity_fix_new_epoch() {
    std::lock_guard lock(g_fail_mu);
    g_failed.store(false);
    g_fail_why.clear();
    g_logout_pending = false;
    g_lobby_user.store(0);
    g_status_key.store(0);
}

std::string identity_fix_describe() {
    std::string s = std::format(
        "C2 identity {}: user 2 = 0x{:X} | lobby loads {} (host {}, user 2 written {} already {} bad {}) | status "
        "written {} already {} bad {}, other characters of user 2 {} | invariant ok {} FAIL {} | Req refused {} | "
        "uniqueness {} (clashes {}, not checked {}) | errors {}",
        g_active.load() ? "on" : (g_wanted.load() ? "WANTED BUT OFF" : "off"), idf::kUser2, g_lobby_loads.load(),
        g_lobby_host.load(), g_lobby_written.load(), g_lobby_already.load(), g_lobby_bad.load(),
        g_status_written.load(), g_status_already.load(), g_status_bad.load(), g_other_chars.load(), g_inv_ok.load(),
        g_inv_fail.load(), g_refused.load(), g_unique_on.load() ? "on" : "off", g_clashes.load(), g_unchecked.load(),
        g_errors.load());
    if (g_failed.load()) {
        std::lock_guard lock(g_fail_mu);
        s += " | FAILED: " + g_fail_why;
    }
    return s;
}

}  // namespace cdmp::session2
