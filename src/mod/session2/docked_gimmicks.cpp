#include "mod/session2/docked_gimmicks.h"

#include <windows.h>
#include <intrin.h>

#include <safetyhook.hpp>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstring>
#include <format>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "mod/game/actor_lookup.h"
#include "mod/game/build_profile.h"
#include "mod/game/hook_prepare.h"
#include "mod/game/offsets.h"
#include "mod/game/player_reader.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/docked_gimmicks_logic.h"
#include "mod/session2/gimmick_event_dedup_logic.h"
#include "mod/session2/gimmick_interact_logic.h"
#include "mod/session2/guest_actor_diag_logic.h"
#include "mod/session2/p8_probe_logic.h"
#include "mod/session2/p8_probes.h"
#include "mod/session2/rope_probe_logic.h"
#include "mod/session2/session2.h"
#include "mod/session2/user2_stages.h"

namespace cdmp::session2 {
namespace {

namespace g2976 = game::build_2976;

constexpr uintptr_t kCodeBegin = 0x1000;
// Where everything is, per build (docked_gimmicks_logic.h). The struct offsets the hooks read are the same in both. Log
// lines keep 2976's names for the functions (the research is written against that build) and print the RVA they use.
struct Addrs {
    uintptr_t client_request, client_request2, client_vtbl, client_slot, err_global;
    std::span<const uint8_t> client_request2_head;
    uintptr_t dock_equip, dock_other, dock_call_site;
    std::span<const uint8_t> dock_call;
    uintptr_t ctl_write, ctl_block, owner_read;
    std::span<const uint8_t> ctl_block_bytes;
    uintptr_t server_execute, server_update;
    std::span<const uint8_t> server_update_head;
    uintptr_t code_end;
    dgl::RecLayout rec;
    // The controller write's verified bytes, the field-owner read's and the register that holds the field there (r13
    // up to 3576; 3663: rdi, docked_gimmicks_logic.h).
    std::span<const uint8_t> ctl_write_bytes{dgl::kControllerWriteBytes};
    std::span<const uint8_t> owner_read_bytes{dgl::kFieldOwnerReadBytes};
    bool field_in_rdi = false;
};
const Addrs kAddrs2976{dgl::kClientRequest, dgl::kClientRequest2, dgl::kClientGimmickVtbl, dgl::kClientGimmickRequestSlot,
                       dgl::kErrNotControllerGlobal, dgl::kClientRequest2Head, dgl::kDockEquip, dgl::kDockOther,
                       dgl::kDockEquipCallSite, dgl::kDockEquipCall, dgl::kControllerWrite, dgl::kControllerBlock,
                       dgl::kFieldOwnerRead, dgl::kControllerBlockBytes, dgl::kServerExecute, dgl::kServerUpdate,
                       dgl::kServerUpdateHead, 0x51EB000, dgl::kRecLayout2976};
const Addrs kAddrs3527{dgl::kClientRequest3527, dgl::kClientRequest23527, dgl::kClientGimmickVtbl3527,
                       dgl::kClientGimmickRequestSlot3527, dgl::kErrNotControllerGlobal3527, dgl::kClientRequest2Head3527,
                       dgl::kDockEquip3527, dgl::kDockOther3527, dgl::kDockEquipCallSite3527, dgl::kDockEquipCall3527,
                       dgl::kControllerWrite3527, dgl::kControllerBlock3527, dgl::kFieldOwnerRead3527,
                       dgl::kControllerBlockBytes3527, dgl::kServerExecute3527, dgl::kServerUpdate3527,
                       dgl::kServerUpdateHead3527, 0x5595000, dgl::kRecLayout3527};
// Build 1.0.0.3576 (static, 2026-11-06; not yet run): docked_gimmicks_logic.h's 3576 table with 3527's bytes, the code
// section's end 0x5597000 (its flags: R-X, 0x1000 + 0x5596000), the 2005 record layout of 3527 (the Troc catalogue and
// message sizes did not change, troc_mapping_3549_3576.json).
const Addrs kAddrs3576{dgl::kClientRequest3576, dgl::kClientRequest23576, dgl::kClientGimmickVtbl3576,
                       dgl::kClientGimmickRequestSlot3576, dgl::kErrNotControllerGlobal3576, dgl::kClientRequest2Head3527,
                       dgl::kDockEquip3576, dgl::kDockOther3576, dgl::kDockEquipCallSite3576, dgl::kDockEquipCall3576,
                       dgl::kControllerWrite3576, dgl::kControllerBlock3576, dgl::kFieldOwnerRead3576,
                       dgl::kControllerBlockBytes3527, dgl::kServerExecute3576, dgl::kServerUpdate3576,
                       dgl::kServerUpdateHead3527, 0x5597000, dgl::kRecLayout3527};
// Build 1.0.0.3663 (static, 2026-11-13; never run): docked_gimmicks_logic.h's 3663 table; the code section's end
// 0x5613000 (its flags: R-X, 0x1000 + 0x5612000); the 2005 record layout of 3527 (game::wire_build(): 3663's payload
// readers are 3527's, build_profile.h; build_ok() admits 3663 only while it says so); the controller write with its own
// bytes and the field in rdi.
const Addrs kAddrs3663{dgl::kClientRequest3663, dgl::kClientRequest23663, dgl::kClientGimmickVtbl3663,
                       dgl::kClientGimmickRequestSlot3663, dgl::kErrNotControllerGlobal3663, dgl::kClientRequest2Head3527,
                       dgl::kDockEquip3663, dgl::kDockOther3663, dgl::kDockEquipCallSite3663, dgl::kDockEquipCall3663,
                       dgl::kControllerWrite3663, dgl::kControllerBlock3663, dgl::kFieldOwnerRead3663,
                       dgl::kControllerBlockBytes3663, dgl::kServerExecute3663, dgl::kServerUpdate3663,
                       dgl::kServerUpdateHead3527, 0x5613000, dgl::kRecLayout3527, dgl::kControllerWriteBytes3663,
                       dgl::kFieldOwnerReadBytes3663, true};
const Addrs& addrs() noexcept {
    static const Addrs& a = game::current_build() == game::Build::v3663   ? kAddrs3663
                            : game::current_build() == game::Build::v3576 ? kAddrs3576
                            : game::current_build() == game::Build::v3527 ? kAddrs3527
                                                                          : kAddrs2976;
    return a;
}
constexpr uint32_t kTickMs = 500;
constexpr uint32_t kWorldTicks = 6;
constexpr uint64_t kMinuteMs = 60000;
constexpr uint64_t kEventLines = 400;
constexpr uint64_t kCheckDelayMs = 1500;
constexpr int kCheckTries = 6;
constexpr uint32_t kUnspawnEventLines = 40;
// REWRITTEN and WITHHELD lines have their own budget, so the shared one cannot starve them.
constexpr uint64_t kPriorityLines = 200;
constexpr uint32_t kUser2ListedLines = 20;

enum EventKind : uint16_t {
    kEvDocked = 1,        // a player-docked 2005 record (v0 key|parent, v1 controller|written, v2 action|role)
    kEvLearnedUser = 2,   // the guest's own user learned (v0 own key|user)
    kEvOwnKey = 3,        // the guest's own character (2756)
    kEvClientFirst = 4,   // first request seen for a gimmick (v0 key|parent, v1 hash|fn, v2 refused)
    kEvClientRefused = 5, // a refused request with a new hash for that gimmick
    kEvDockEntry = 6,     // a docking spawn for a PLAYER character (v0 parent|controller, v1 type|which)
    kEvDockCreate = 7,    // an actor created inside it (v0 key|type, v1 eax|field owner, v2 parent|which)
    kEvServerReject = 8,  // first rejection per gimmick at the server (v0 key|controller, v1 requester|hash, v2 op)
    kEvUnspawn = 9,       // a 2221 (v0 key|from, v1 other's age ms, v2 own age ms)
    kEvWithheld = 10,     // first withheld / would-withhold per key and op (v0 key|op, v1 mode)
    kEvMalformed = 11,    // a 2005 whose record lengths do not add up
    kEvUser2Listed = 12,  // host: user 2 sent a listed state request for a gimmick docked to a player (v0 key|op, v1 parent)
    kEvRetired = 13,      // guest: a local-only key dropped (v0 key, v1 why: 0 another parent / not docked, 1 2516)
    kEvDedupGuest = 14,   // gimmick_event_dedup, guest: an outgoing 2779 (v0 key|controller, v1 own user|verdict, v2 action)
    kEvDedupCreated = 15, // gimmick_event_dedup, host: a 2250 index > 1 (v0 key|index, v1 kind|trigger, v2 gap,
                          // v3 counts)
    kEvUser2Host = 16,    // host (review M1): a Req of user 2 naming the host's device / character (v0 op|which|at,
                          // v1 key, v2 n)
    kEvGiTrace = 17       // guest_gimmick_interact: a refused (or let through) request (v0 key|fn<<32|let<<33, v1 hash|
                          // caller rva<<32, v2 actor, v3 controller)
};

std::atomic<bool> g_started{false}, g_guest{false};
std::atomic<uint8_t> g_mode{0};  // dgl::Mode
std::atomic<bool> g_client_hooks{false}, g_server_hooks{false}, g_server_probe{false};
uintptr_t g_base = 0;
std::atomic<uint32_t> g_err_code{dgl::kErrNotController};

dgl::Mode mode() { return static_cast<dgl::Mode>(g_mode.load(std::memory_order_relaxed)); }
// [session2] docked_gimmicks_other (guest only): in effect only while docked_gimmicks is on (its delivery and send
// points carry it).
std::atomic<uint8_t> g_other_mode{0};
dgl::Mode other_mode() {
    if (mode() == dgl::Mode::Off) return dgl::Mode::Off;
    return static_cast<dgl::Mode>(g_other_mode.load(std::memory_order_relaxed));
}
// [session2] gimmick_event_dedup (gimmick_event_dedup_logic.h): its own mode, the same module's hooks and thread.
std::atomic<uint8_t> g_dedup_mode{0};
dgl::Mode dedup_mode() { return static_cast<dgl::Mode>(g_dedup_mode.load(std::memory_order_relaxed)); }
bool any_mode() { return mode() != dgl::Mode::Off || dedup_mode() != dgl::Mode::Off; }
// [session2] guest_gimmick_interact (gimmick_interact_logic.h): guest only, needs docked_gimmicks' client hooks. The list
// is written once before the hooks go in and only read after.
std::atomic<uint8_t> g_gi_mode{0};  // gil::Mode
gil::Events g_gi_events;
gil::Mode gi_mode() { return static_cast<gil::Mode>(g_gi_mode.load(std::memory_order_relaxed)); }
std::atomic<bool> g_gi_hooks{false};
std::atomic<uint64_t> g_gi_let{0}, g_gi_refused{0}, g_gi_lines_dropped{0};
// This thread's request call (the compares run inside it, on the same thread): may it pass, and did it.
struct GiCall {
    bool allow = false;
    bool let = false;
};
thread_local GiCall t_gi;
constexpr uint32_t kDedupGuestLines = 200;
constexpr uint32_t kDedupHostLines = 100;

p8p::EventRing<1024> g_ring;
std::atomic<uint32_t> g_seq{0};
uint32_t next_seq() { return g_seq.fetch_add(1, std::memory_order_relaxed) + 1; }
void push(uint16_t kind, uint64_t v0, uint64_t v1 = 0, uint64_t v2 = 0, uint64_t v3 = 0) noexcept {
    p8p::Event e;
    e.qpc_us = p8_now_us();
    e.tid = GetCurrentThreadId();
    e.kind = kind;
    e.v[0] = v0;
    e.v[1] = v1;
    e.v[2] = v2;
    e.v[3] = v3;
    e.v[11] = next_seq();
    g_ring.push(e);
}

// ---------------------------------------------------------------- the 2005 counters (both roles)

struct Counts2005 {
    std::atomic<uint64_t> packets{0}, records{0}, gimmicks{0}, not_docked{0}, docked_world{0}, docked_player{0};
    std::atomic<uint64_t> rewritten{0}, would_rewrite{0}, already_mine{0}, own_user_unknown{0}, own_key_unknown{0},
        other_player{0}, malformed{0}, faults{0}, not_user_controller{0}, not_game_mechanic{0},
        malformed_not_written{0}, retired{0}, retired_2516{0}, other_rewritten{0}, other_would_rewrite{0},
        other_unchanged{0};
};
Counts2005 g_c;
// Gimmick keys docked to a player character seen in a 2005 (both roles): the server probe logs its rejections
// only for these (the others are counted).
dgl::KeySet<128> g_player_docked;

void count(const dgl::Result2005& r) {
    g_c.packets.fetch_add(1, std::memory_order_relaxed);
    g_c.records.fetch_add(r.records, std::memory_order_relaxed);
    g_c.gimmicks.fetch_add(r.gimmicks, std::memory_order_relaxed);
    g_c.not_docked.fetch_add(r.not_docked, std::memory_order_relaxed);
    g_c.docked_world.fetch_add(r.docked_world, std::memory_order_relaxed);
    g_c.docked_player.fetch_add(r.docked_player, std::memory_order_relaxed);
    g_c.rewritten.fetch_add(r.rewritten, std::memory_order_relaxed);
    g_c.would_rewrite.fetch_add(r.would_rewrite, std::memory_order_relaxed);
    g_c.already_mine.fetch_add(r.already_mine, std::memory_order_relaxed);
    g_c.own_user_unknown.fetch_add(r.own_user_unknown, std::memory_order_relaxed);
    g_c.own_key_unknown.fetch_add(r.own_key_unknown, std::memory_order_relaxed);
    g_c.other_player.fetch_add(r.other_player, std::memory_order_relaxed);
    if (r.malformed) g_c.malformed.fetch_add(1, std::memory_order_relaxed);
    g_c.not_user_controller.fetch_add(r.not_user_controller, std::memory_order_relaxed);
    g_c.not_game_mechanic.fetch_add(r.not_game_mechanic, std::memory_order_relaxed);
    g_c.malformed_not_written.fetch_add(r.malformed_not_written, std::memory_order_relaxed);
    g_c.retired.fetch_add(r.retired, std::memory_order_relaxed);
    g_c.other_rewritten.fetch_add(r.other_rewritten, std::memory_order_relaxed);
    g_c.other_would_rewrite.fetch_add(r.other_would_rewrite, std::memory_order_relaxed);
    g_c.other_unchanged.fetch_add(r.other_unchanged, std::memory_order_relaxed);
}

// Gimmick key -> its docked player parent, from the 2005s (host: its client's, the sniffer's writer thread writes, the
// server's receive thread reads; both roles: the client probe's class, read on the game's threads). Fixed size,
// oldest overwritten; the guest clears it at every world change (keys repeat across worlds).
class DockedMap {
public:
    void clear() {
        for (auto& e : e_) e.store(0, std::memory_order_relaxed);
    }
    void put(uint32_t key, uint32_t parent) {
        const uint64_t v = key | (uint64_t{parent} << 32);
        for (auto& e : e_) {
            if (static_cast<uint32_t>(e.load(std::memory_order_relaxed)) == key) {
                e.store(v, std::memory_order_relaxed);
                return;
            }
        }
        e_[next_.fetch_add(1, std::memory_order_relaxed) % std::size(e_)].store(v, std::memory_order_relaxed);
    }
    uint32_t parent_of(uint32_t key) const {
        if (!key) return 0;
        for (const auto& e : e_) {
            const uint64_t v = e.load(std::memory_order_relaxed);
            if (static_cast<uint32_t>(v) == key) return static_cast<uint32_t>(v >> 32);
        }
        return 0;
    }

private:
    std::atomic<uint64_t> e_[128] = {};
    std::atomic<uint32_t> next_{0};
};
DockedMap g_docked_map;
std::atomic<uint32_t> g_host_own_key{0};  // host: its own character (the sniffed 2756)
// Host: the last player character other than its own that a sniffed 2005 docked a gimmick to (user 2's), for the
// distance between the players in gimmick_event_dedup's lone-2779 lines.
std::atomic<uint32_t> g_host_user2_char{0};
// Host, item 1 of the S28 review: user 2's listed state requests (kWithheldOps) for gimmicks docked to a player,
// at the server's receive: [0] docked to a character that is not the host's (user 2's own), [1] docked to the
// host's, [2] the host's own character not known yet. Expected in step 1 ~16 (one 2758 + one 2774 per device at its
// creation), in step 2 (guest docked_gimmicks=1) 0.
std::atomic<uint64_t> g_user2_listed[3][dgl::kWithheldOpCount] = {};
std::atomic<uint32_t> g_user2_listed_lines{0};
// Host, review M1 of d5fdf82 (log only): user 2's requests of ANY opcode whose key at +0 or +1 (the u8 4 prefix of
// 2249 / 2380 / ...) is [0] a gimmick docked to the HOST's character (its device) or [1] the host's character itself.
// With docked_gimmicks_other=1 the guest's client believes it controls the host's device: a request outside
// kWithheldOps (transform 2556 / 2828 / 3067, 2221...) or one keyed by the device's parent would show here as growth
// from step 1 to step 2. Per opcode (< kOpSlots); the first kUser2HostLinesPerOp per opcode logged (kUser2HostLines
// in all).
constexpr size_t kOpSlots = 4096;
constexpr uint32_t kUser2HostLinesPerOp = 3;
constexpr uint32_t kUser2HostLines = 80;
std::atomic<uint32_t> g_user2_host[2][kOpSlots] = {};
std::atomic<uint64_t> g_user2_host_at1[2] = {};  // of them, found at +1
std::atomic<uint32_t> g_user2_host_lines{0};
void push_docked(const dgl::Result2005& r, bool host) {
    for (size_t i = 0; i < r.docked_n; ++i) {
        const dgl::Docked& d = r.docked[i];
        g_player_docked.add(d.key);
        g_docked_map.put(d.key, d.parent);  // both roles: the client probe's class (and the host's listed counter)
        if (host) {
            const uint32_t own = g_host_own_key.load(std::memory_order_relaxed);
            if (own && d.parent != own) g_host_user2_char.store(d.parent, std::memory_order_relaxed);
        }
        p8p::Event e;
        e.qpc_us = p8_now_us();
        e.tid = GetCurrentThreadId();
        e.kind = kEvDocked;
        e.v[0] = d.key | (uint64_t{d.parent} << 32);
        e.v[1] = d.controller | (uint64_t{d.written} << 32);
        e.v[2] = static_cast<uint64_t>(d.action) | (uint64_t{host ? 1u : 0u} << 8) | (uint64_t{d.other ? 1u : 0u} << 9);
        static_assert(sizeof d.name == 3 * sizeof(uint64_t));
        std::memcpy(&e.v[3], d.name, sizeof d.name);  // v[3..5]: the record's name (ASCII, terminated)
        e.v[11] = next_seq();
        g_ring.push(e);
    }
    if (r.malformed) push(kEvMalformed, r.records);
}

// ---------------------------------------------------------------- guest: packets only

// Own key (2756) and own user: written by the delivery (the client's NetworkThread, in order with the 2005s); read
// by the summary. Reset (a new conversation, the connection's end) clears both.
std::atomic<uint32_t> g_own_key{0}, g_own_user{0};
dgl::LocalKeys g_keys;
// [0] keys docked to the own character (phase 1), [1] to the other player's (docked_gimmicks_other).
std::atomic<uint64_t> g_withheld[2][dgl::kWithheldOpCount] = {}, g_would_withhold[2][dgl::kWithheldOpCount] = {};
std::atomic<uint64_t> g_resets{0};
// The first withheld (or would-withhold) per key and op: a tiny log-once set (the send thread).
std::atomic<uint64_t> g_withheld_logged[64] = {};
bool first_withheld(uint32_t key, uint16_t op) {
    const uint64_t v = key | (uint64_t{op} << 32);
    for (auto& s : g_withheld_logged) {
        uint64_t cur = s.load(std::memory_order_relaxed);
        if (cur == v) return false;
        if (cur == 0 && s.compare_exchange_strong(cur, v, std::memory_order_relaxed)) return true;
        if (cur == v) return false;
    }
    return false;
}

// ---------------------------------------------------------------- the hooks' tables (game threads)

dgl::Table<dgl::ClientEntry, 8192> g_client;
dgl::Table<dgl::ServerEntry, 4096> g_server;
dgl::Table<dgl::TouchEntry, 8192> g_touch;
std::atomic<uint64_t> g_client_untracked{0}, g_server_untracked{0};
std::atomic<uint64_t> g_creations_in_dock{0}, g_dock_entries[2] = {}, g_dock_entries_player[2] = {};
std::atomic<uint64_t> g_server_counts[2][2][2] = {};  // [op 0 exec / 1 update][requester 0 field owner / 1 other][0 ok / 1 rejected]
std::atomic<uint32_t> g_field_owner{0};  // the field owner the controller write saw ([r13+0x180])
std::atomic<uint64_t> g_unspawn[2][dgl::kAgeBuckets] = {};  // [from 0 host / 1 user 2][the OTHER's age bucket]
std::atomic<uint64_t> g_unspawn_reqs[2] = {}, g_spawn_reqs[2] = {}, g_touches{0};
std::atomic<uint32_t> g_unspawn_lines{0};
std::atomic<uint64_t> g_unspawn_keys_not_measured{0};  // keys of a 2221 past the 16 the probe reads

// gimmick_event_dedup. Guest: each gimmick's controller as the server sent it; the 2779 verdicts [verdict][0 sent /
// 1 would withhold (probe) / 2 withheld]. Host: 2779 per origin and key, 2250 per kind.
ged::ControllerMap g_ctl_map;
std::atomic<uint64_t> g_ged_guest[static_cast<size_t>(ged::Verdict::Count)][3] = {};
std::atomic<uint32_t> g_ged_guest_lines{0};
ged::DupTable g_dup;
std::atomic<uint64_t> g_ged_2779[2] = {}, g_ged_created[static_cast<size_t>(ged::Created::Count)] = {},
    g_ged_2250_untracked{0}, g_ged_2779_untracked{0};
std::atomic<uint32_t> g_ged_host_lines{0};

int access_filter(const EXCEPTION_POINTERS* ep) noexcept {
    const EXCEPTION_RECORD* r = ep ? ep->ExceptionRecord : nullptr;
    if (!r) return EXCEPTION_CONTINUE_SEARCH;
    return r->ExceptionCode == EXCEPTION_ACCESS_VIOLATION || r->ExceptionCode == EXCEPTION_IN_PAGE_ERROR
               ? EXCEPTION_EXECUTE_HANDLER
               : EXCEPTION_CONTINUE_SEARCH;
}
bool plausible(uintptr_t a, size_t n) { return a >= 0x10000 && a <= 0x00007FFFFFFFFFFFull - n; }
// A slot in the CALLER's frame on this thread (the error code, an event on the caller's stack): plain SEH reads
// (game::fast_read is not meant for thread stacks).
bool seh_copy(uintptr_t a, void* out, size_t n) noexcept {
    if (!plausible(a, n)) return false;
    __try {
        const volatile uint8_t* s = reinterpret_cast<const volatile uint8_t*>(a);
        uint8_t* d = static_cast<uint8_t*>(out);
        for (size_t i = 0; i < n; ++i) d[i] = s[i];
        return true;
    } __except (access_filter(GetExceptionInformation())) {
        return false;
    }
}

using Arg = uint64_t;
SafetyHookInline g_req_hook, g_req2_hook, g_dock_hook, g_dock2_hook, g_exec_hook, g_upd_hook;
SafetyHookMid g_ctl_mid;
// The controller write 0x2792A7B has one hook and two possible users (docked_gimmicks.h): who asked for it. 0 = not
// installed; the callback asks user2_stages only while its bit is set.
constexpr uint8_t kCtlUserDocked = 1, kCtlUserU2 = 2;
std::atomic<uint8_t> g_ctl_users{0};
std::mutex g_ctl_mx;

// ---------------------------------------------------------------- client: the event requests (log only)

struct ClientPre {
    uint32_t key = 0;
    uint32_t parent = 0xFFFFFFFFu;
    uint32_t hash = 0;
};
ClientPre client_pre(Arg comp, Arg ev) noexcept {
    ClientPre p;
    if (const auto actor = game::fast_ptr(comp + dgl::kComp_Actor)) {
        if (const auto k = game::fast<uint32_t>(*actor + dgl::kActor_Key)) p.key = *k;
    }
    // The class comes from the player parent the key's 2005 named (P8 S29): the component's +0x2B4 read 0 for every
    // player-docked gimmick in S28, so every device fell in the world class.
    if (p.key) p.parent = g_docked_map.parent_of(p.key);
    (void)seh_copy(ev, &p.hash, sizeof p.hash);
    return p;
}
void gi_trace(int fn, const ClientPre& p, Arg comp, uintptr_t ret, bool refused, bool let) noexcept {
    if (gi_mode() == gil::Mode::Off || !(refused || let)) return;
    (refused ? g_gi_refused : g_gi_let).fetch_add(1, std::memory_order_relaxed);
    uint64_t actor = 0;
    uint32_t ctl = 0;
    if (const auto a = game::fast_ptr(comp + dgl::kComp_Actor)) {
        actor = *a;
        if (const auto c = game::fast<uint32_t>(actor + dgl::kActor_Controller)) ctl = *c;
    }
    const uint64_t caller = ret >= g_base && ret - g_base < 0xFFFFFFFFull ? ret - g_base : 0;
    push(kEvGiTrace, p.key | (uint64_t(fn & 1) << 32) | (uint64_t(let) << 33), p.hash | (caller << 32), actor, ctl);
}
void client_post(int fn, const ClientPre& p, Arg err) noexcept {
    uint32_t code = 0;
    const bool refused = seh_copy(err, &code, sizeof code) && code == g_err_code.load(std::memory_order_relaxed);
    dgl::ClientEntry* e = p.key ? g_client.get(p.key) : nullptr;
    if (!e) {
        g_client_untracked.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (p.parent != 0xFFFFFFFFu) e->parent.store(p.parent, std::memory_order_relaxed);
    const uint32_t before = e->calls[0].load(std::memory_order_relaxed) + e->calls[1].load(std::memory_order_relaxed);
    e->calls[fn].fetch_add(1, std::memory_order_relaxed);
    if (before == 0) e->first_hash.store(p.hash, std::memory_order_relaxed);
    e->last_hash.store(p.hash, std::memory_order_relaxed);
    if (refused) {
        e->refused[fn].fetch_add(1, std::memory_order_relaxed);
        if (e->last_refused_hash.exchange(p.hash, std::memory_order_relaxed) != p.hash && before != 0 &&
            dgl::player_key(p.parent)) {
            push(kEvClientRefused, p.key | (uint64_t{p.parent} << 32), p.hash | (uint64_t(fn) << 32), 1);
        }
    }
    // World and NPC gimmicks (thousands): the summary counts them; a line only for the player-docked ones.
    if (before == 0 && dgl::player_key(p.parent)) {
        push(kEvClientFirst, p.key | (uint64_t{p.parent} << 32), p.hash | (uint64_t(fn) << 32), refused);
    }
}
bool refused_now(Arg err) noexcept {
    uint32_t code = 0;
    return seh_copy(err, &code, sizeof code) && code == g_err_code.load(std::memory_order_relaxed);
}
// guest_gimmick_interact: the decision for this call (its compare reads t_gi). Saved and put back around the call: a
// request may run another one inside it.
Arg req_detour(Arg comp, Arg err, Arg ev, Arg p4) {
    const uintptr_t ret = reinterpret_cast<uintptr_t>(_ReturnAddress());
    const ClientPre p = client_pre(comp, ev);
    const GiCall saved = t_gi;
    t_gi = GiCall{g_gi_hooks.load(std::memory_order_relaxed) && gil::allow(gi_mode(), g_gi_events, p.hash), false};
    const Arg r = g_req_hook.unsafe_call<Arg>(comp, err, ev, p4);
    const bool let = t_gi.let;
    t_gi = saved;
    client_post(0, p, err);
    gi_trace(0, p, comp, ret, refused_now(err), let);
    return r;
}
Arg req2_detour(Arg comp, Arg err, Arg ev, Arg p4, Arg p5) {
    const uintptr_t ret = reinterpret_cast<uintptr_t>(_ReturnAddress());
    const ClientPre p = client_pre(comp, ev);
    const GiCall saved = t_gi;
    t_gi = GiCall{g_gi_hooks.load(std::memory_order_relaxed) && gil::allow(gi_mode(), g_gi_events, p.hash), false};
    const Arg r = g_req2_hook.unsafe_call<Arg>(comp, err, ev, p4, p5);
    const bool let = t_gi.let;
    t_gi = saved;
    client_post(1, p, err);
    gi_trace(1, p, comp, ret, refused_now(err), let);
    return r;
}
// The compares 0x9D0641 (actor in rsi) / 0x9D0B6F (r13): eax = this client's user. For a call t_gi allows, eax := the
// gimmick's controller, so the je takes the accepted path (which overwrites rax at once).
void gi_compare(safetyhook::Context& ctx, uintptr_t actor) noexcept {
    if (!t_gi.allow) return;
    const auto c = game::fast<uint32_t>(actor + dgl::kActor_Controller);
    if (!c || *c == static_cast<uint32_t>(ctx.rax)) return;
    ctx.rax = *c;
    t_gi.let = true;
}
void gi_compare_mid(safetyhook::Context& ctx) { gi_compare(ctx, ctx.rsi); }
void gi_compare2_mid(safetyhook::Context& ctx) { gi_compare(ctx, ctx.r13); }
SafetyHookMid g_gi_mid, g_gi_mid2;

// ---------------------------------------------------------------- server (host): docking context (log only)

struct DockCtx {
    uint32_t parent = 0;
    uint32_t parent_ctl = 0;
    uint8_t type = 0;
    uint8_t which = 0;
    uint32_t created = 0;  // actors the controller write saw inside this call
};
thread_local DockCtx t_dock{};

Arg dock_common(int which, SafetyHookInline& hook, Arg comp, Arg err, Arg req) {
    const DockCtx saved = t_dock;
    DockCtx c;
    c.which = static_cast<uint8_t>(which);
    if (const auto actor = game::fast_ptr(comp + 8)) {
        if (const auto k = game::fast<uint32_t>(*actor + dgl::kActor_Key)) c.parent = *k;
        if (const auto ctl = game::fast<uint32_t>(*actor + dgl::kActor_Controller)) c.parent_ctl = *ctl;
        if (const auto ti = game::fast_ptr(*actor + dgl::kActor_TypeInfo)) {
            if (const auto t = game::fast<uint8_t>(*ti + 1)) c.type = *t;
        }
    }
    g_dock_entries[which].fetch_add(1, std::memory_order_relaxed);
    if (dgl::player_key(c.parent)) g_dock_entries_player[which].fetch_add(1, std::memory_order_relaxed);
    t_dock = c.parent ? c : DockCtx{};
    const Arg r = hook.unsafe_call<Arg>(comp, err, req);
    const uint32_t created = t_dock.created;
    t_dock = saved;
    // The 2249 loop calls this hundreds of times per character with nothing to create: a line only when it created.
    if (created && dgl::player_key(c.parent)) {
        push(kEvDockEntry, c.parent | (uint64_t{c.parent_ctl} << 32), c.type | (uint64_t(which) << 8), created);
    }
    return r;
}
Arg dock_detour(Arg comp, Arg err, Arg req) { return dock_common(0, g_dock_hook, comp, err, req); }
Arg dock2_detour(Arg comp, Arg err, Arg req) { return dock_common(1, g_dock2_hook, comp, err, req); }

// 0x2792A7B, mov [r14+0x90],eax: read only for docked_gimmicks.
void ctl_write_mid(safetyhook::Context& ctx) {
    // The field: r13 up to 3576, rdi on 3663 (Addrs::field_in_rdi, the verified owner read before the write).
    const uintptr_t field = addrs().field_in_rdi ? ctx.rdi : ctx.r13;
    // user2_npc_control (U-e, user2_stages.h) first: it may set eax, the controller about to be written (a register
    // only); it returns at once unless user 2's armed timer is creating an NPC.
    if (g_ctl_users.load(std::memory_order_relaxed) & kCtlUserU2) {
        uintptr_t rax = ctx.rax;
        user2_stages_npc_control(rax, ctx.rsi, field, ctx.r14);
        ctx.rax = rax;
    }
    // Every actor creation passes here: the per-thread variable first, nothing else outside a docking spawn.
    if (!t_dock.parent) return;
    ++t_dock.created;
    const DockCtx c = t_dock;
    g_creations_in_dock.fetch_add(1, std::memory_order_relaxed);
    uint32_t key = 0, owner = 0;
    uint8_t type = 0;
    if (const auto k = game::fast<uint32_t>(ctx.r14 + dgl::kActor_Key)) key = *k;
    if (const auto ti = game::fast_ptr(ctx.r14 + dgl::kActor_TypeInfo)) {
        if (const auto t = game::fast<uint8_t>(*ti + 1)) type = *t;
    }
    if (const auto o = game::fast<uint32_t>(field + dgl::kField_Owner)) {
        owner = *o;
        g_field_owner.store(owner, std::memory_order_relaxed);
    }
    if (dgl::player_key(c.parent)) {
        push(kEvDockCreate, key | (uint64_t{type} << 32), static_cast<uint32_t>(ctx.rax) | (uint64_t{owner} << 32),
             c.parent | (uint64_t{c.which} << 32), c.parent_ctl);
    }
}

// ---------------------------------------------------------------- server (host): accepted / rejected

struct ServerPre {
    uint32_t key = 0, controller = 0, requester = 0;
    bool read = false;
};
ServerPre server_pre(Arg comp, Arg user) noexcept {
    ServerPre p;
    const auto actor = game::fast_ptr(comp + 8);
    if (!actor) return p;
    const auto k = game::fast<uint32_t>(*actor + dgl::kActor_Key);
    const auto ctl = game::fast<uint32_t>(*actor + dgl::kActor_Controller);
    if (!k || !ctl) return p;
    p.key = *k;
    p.controller = *ctl;
    if (const auto owner = game::fast_ptr(user + dgl::kUser_Owner)) {
        if (const auto u = game::fast<uint32_t>(*owner + dgl::kActor_Key)) p.requester = *u;
    }
    p.read = true;
    return p;
}
void server_count(int op, const ServerPre& p, bool rejected, uint32_t hash) noexcept {
    if (!p.read) return;
    const uint32_t fo = g_field_owner.load(std::memory_order_relaxed);
    const int who = (fo && p.requester == fo) ? 0 : 1;
    g_server_counts[op][who][rejected ? 1 : 0].fetch_add(1, std::memory_order_relaxed);
    dgl::ServerEntry* e = g_server.get(p.key);
    if (!e) {
        g_server_untracked.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    e->last_requester.store(p.requester, std::memory_order_relaxed);
    e->last_controller.store(p.controller, std::memory_order_relaxed);
    e->last_hash.store(hash, std::memory_order_relaxed);
    if (rejected) {
        // A line for the first rejection of a gimmick docked to a player (the others: counted).
        if (e->rejected[0].load(std::memory_order_relaxed) + e->rejected[1].load(std::memory_order_relaxed) == 0 &&
            g_player_docked.contains(p.key)) {
            push(kEvServerReject, p.key | (uint64_t{p.controller} << 32), p.requester | (uint64_t{hash} << 32),
                 static_cast<uint64_t>(op));
        }
        e->rejected[op].fetch_add(1, std::memory_order_relaxed);
    } else {
        e->accepted[op].fetch_add(1, std::memory_order_relaxed);
    }
}
void exec_detour(Arg comp, Arg user, Arg ev, Arg p4) {
    const ServerPre p = server_pre(comp, user);
    uint32_t hash = 0;
    (void)seh_copy(ev, &hash, sizeof hash);  // the handler's local event (its stack)
    g_exec_hook.unsafe_call<void>(comp, user, ev, p4);
    // 0x2AC1270 returns nothing: its own test (gimmick +0x90 == requester's user) decides, recomputed here.
    server_count(0, p, p.controller != p.requester, hash);
}
Arg upd_detour(Arg comp, Arg err, Arg user, Arg data) {
    const ServerPre p = server_pre(comp, user);
    uint32_t hash = 0;
    (void)seh_copy(data, &hash, sizeof hash);  // the handler's local data (its stack)
    const Arg r = g_upd_hook.unsafe_call<Arg>(comp, err, user, data);
    uint32_t code = 0;
    const bool rejected = seh_copy(err, &code, sizeof code) && code == g_err_code.load(std::memory_order_relaxed);
    server_count(1, p, rejected, hash);
    return r;
}

// ---------------------------------------------------------------- install (the module's thread, world up)

bool bytes_at(uintptr_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::equal(actual.begin(), actual.end(), expected.begin());
}

struct Prepared {
    SafetyHookInline* slot = nullptr;
    std::optional<SafetyHookInline> hook;
};

bool prepare(uintptr_t rva, void* detour, std::span<const uint8_t> head, const char* what, SafetyHookInline& slot,
             std::vector<Prepared>& out) {
    auto whole = [&](const std::vector<uint8_t>& o) {
        return o.size() == dgl::kEntryPatch && o.size() <= head.size() && std::memcmp(o.data(), head.data(), o.size()) == 0;
    };
    auto h = game::prepare_inline(g_base + rva, detour, whole, "DockedGimmicks", what);
    if (!h) {
        log::error("DockedGimmicks: the hook on {} (exe+0x{:X}) could not be prepared ({}); REFUSED, nothing written",
                   what, rva, game::inline_error_text(h.error()));
        return false;
    }
    if (!whole(h->original_bytes())) {
        log::error("DockedGimmicks: the hook on {} (exe+0x{:X}) would patch {} bytes, not the verified 5-byte "
                   "instruction; REFUSED, nothing written",
                   what, rva, h->original_bytes().size());
        return false;
    }
    Prepared p;
    p.slot = &slot;
    p.hook = std::move(*h);
    out.push_back(std::move(p));
    return true;
}

bool enable_all(std::vector<Prepared>& ready, const char* group) {
    for (Prepared& p : ready) *p.slot = std::move(*p.hook);
    std::vector<SafetyHookInline*> enabled;
    for (Prepared& p : ready) {
        if (!p.slot->enable()) {
            log::error("DockedGimmicks: a {} hook could not be enabled; the others are put back; REFUSED", group);
            for (SafetyHookInline* h : enabled) (void)h->disable();
            return false;
        }
        enabled.push_back(p.slot);
    }
    return true;
}

struct Check {
    uintptr_t rva;
    std::span<const uint8_t> bytes;
    const char* what;
};
bool checks_ok(std::span<const gad::Section> secs, std::span<const Check> checks) {
    for (const Check& c : checks) {
        const bool in_code = c.rva >= kCodeBegin && c.rva + c.bytes.size() <= addrs().code_end &&
                             gad::in_real_code(secs, static_cast<uint32_t>(c.rva), static_cast<uint32_t>(c.bytes.size()));
        if (!in_code || !bytes_at(c.rva, c.bytes)) {
            log::error("DockedGimmicks: {} (exe+0x{:X}, {} bytes) is not this build's expected code; REFUSED, nothing "
                       "written",
                       c.what, c.rva, c.bytes.size());
            return false;
        }
    }
    return true;
}

void install_interact(std::span<const gad::Section> secs);
void install_client(std::span<const gad::Section> secs) {
    const Addrs& ad = addrs();
    const Check checks[] = {
        {ad.client_request, dgl::kClientRequestHead, "the client's gimmick event request's entry"},
        {ad.client_request2, ad.client_request2_head, "the client's second gimmick request's entry"},
    };
    if (!checks_ok(secs, checks)) return;
    uint64_t slot = 0;
    if (!game::safe_read(g_base + ad.client_slot, &slot, sizeof slot) || slot != g_base + ad.client_request) {
        log::error("DockedGimmicks: pa::ClientGimmickActorComponent's vtable slot (exe+0x{:X}) does not hold exe+0x{:X}; "
                   "REFUSED, nothing written",
                   ad.client_slot, ad.client_request);
        return;
    }
    std::vector<Prepared> ready;
    if (!prepare(ad.client_request, reinterpret_cast<void*>(&req_detour), dgl::kClientRequestHead,
                 "the gimmick event request", g_req_hook, ready) ||
        !prepare(ad.client_request2, reinterpret_cast<void*>(&req2_detour), ad.client_request2_head,
                 "the second gimmick request", g_req2_hook, ready) ||
        !enable_all(ready, "client")) {
        return;
    }
    g_client_hooks.store(true);
    log::info("DockedGimmicks: client probe hooked at the entries of exe+0x{:X} and exe+0x{:X} (5 bytes each); log only, "
              "nothing of the game is written",
              ad.client_request, ad.client_request2);
    install_interact(secs);
}

// guest_gimmick_interact = 1: the two compares (builds 3527 / 3549 / 3576 only; trace needs no hook of its own).
void install_interact(std::span<const gad::Section> secs) {
    const gil::Mode m = gi_mode();
    if (m == gil::Mode::Off || !g_guest.load()) return;
    if (m == gil::Mode::Trace) {
        log::info("GimmickInteract (guest_gimmick_interact=trace): the refused requests are traced at the entry hooks; "
                  "nothing passes");
        return;
    }
    const game::Build build = game::current_build();
    if (build != game::Build::v3527 && build != game::Build::v3576 && build != game::Build::v3663) {
        log::error("GimmickInteract: guest_gimmick_interact=1 has no compare addresses for this build; it stays trace");
        return;
    }
    // 3576 / 3663: the same compares (3527's bytes and patches) at docked_gimmicks_logic.h's addresses of the build.
    const uintptr_t check1 = build == game::Build::v3663   ? dgl::kClientCheck3663
                             : build == game::Build::v3576 ? dgl::kClientCheck3576
                                                           : dgl::kClientCheck3527;
    const uintptr_t check2 = build == game::Build::v3663   ? dgl::kClientCheck23663
                             : build == game::Build::v3576 ? dgl::kClientCheck23576
                                                           : dgl::kClientCheck23527;
    if (!p8_install_mid(g_base, secs, check1, dgl::kClientCheckPatch3527, dgl::kClientCheckBytes3527, &gi_compare_mid,
                        g_gi_mid, "GimmickInteract", "the request's control compare (cmp eax,[rsi+0x90])") ||
        !p8_install_mid(g_base, secs, check2, dgl::kClientCheck2Patch3527, dgl::kClientCheck2Bytes3527, &gi_compare2_mid,
                        g_gi_mid2, "GimmickInteract", "the second request's control compare (cmp eax,[r13+0x90])")) {
        g_gi_mid = {};
        g_gi_mid2 = {};
        log::error("GimmickInteract: not both compares could be hooked; nothing passes (trace goes on)");
        return;
    }
    g_gi_hooks.store(true);
    std::string list;
    for (size_t i = 0; i < g_gi_events.n; ++i) list += std::format("{}0x{:08X}", list.empty() ? "" : ", ", g_gi_events.hash[i]);
    log::info("GimmickInteract (guest_gimmick_interact=1): compares exe+0x{:X} / exe+0x{:X} hooked; a request refused "
              "only because the host controls the gimmick passes for the events [{}]",
              check1, check2, list.empty() ? std::string("none listed") : list);
}

// The one install of 0x2792A7B for whichever user asks first (docked_gimmicks' worker, user2_stages' thread: the lock
// serialises them). Its own base and section table: docked_gimmicks may be off (g_base unset). The write, the block's
// head (r14 / rsi) and the field-owner read (r13) compared first; nothing written otherwise.
bool ctl_write_acquire(uint8_t user, const char* who) {
    std::lock_guard<std::mutex> lock(g_ctl_mx);
    if (g_ctl_users.load() != 0) {
        g_ctl_users.fetch_or(user);
        return true;
    }
    const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    const Addrs& ad = addrs();
    std::vector<gad::Section> secs;
    if (base != g2976::kImageBase || !p8_exe_sections(base, secs)) {
        log::error("{}: the server's controller write exe+0x{:X}: unsupported build or unreadable sections; REFUSED", who,
                   ad.ctl_write);
        return false;
    }
    const auto same = [&](uintptr_t rva, std::span<const uint8_t> expected) {
        std::vector<uint8_t> actual(expected.size());
        return game::safe_read(base + rva, actual.data(), actual.size()) &&
               std::equal(actual.begin(), actual.end(), expected.begin());
    };
    if (!same(ad.ctl_block, ad.ctl_block_bytes) || !same(ad.owner_read, ad.owner_read_bytes)) {
        log::error("{}: the controller block exe+0x{:X} / the field-owner read exe+0x{:X} are not this build's expected "
                   "code; exe+0x{:X} REFUSED, nothing written",
                   who, ad.ctl_block, ad.owner_read, ad.ctl_write);
        return false;
    }
    if (!p8_install_mid(base, secs, ad.ctl_write, dgl::kControllerWritePatch, ad.ctl_write_bytes, &ctl_write_mid,
                        g_ctl_mid, who,
                        "the server's controller write (mov [r14+0x90],eax; one hook for docked_gimmicks and "
                        "user2_npc_control)")) {
        return false;
    }
    g_ctl_users.store(user);
    return true;
}
// A user that no longer needs it; the last one takes the hook out. Review 9 of ae14ab6 (pre-existing, as before the
// shared install): only docked_gimmicks' failed enable calls this, and destroying the mid hook relies on safetyhook's
// disable (the other threads frozen, their instruction pointers moved off the patch) for a callback in flight; with
// user2_npc_control also a user the hook is never taken out.
void ctl_write_release(uint8_t user) {
    std::lock_guard<std::mutex> lock(g_ctl_mx);
    const uint8_t left = static_cast<uint8_t>(g_ctl_users.fetch_and(static_cast<uint8_t>(~user)) & ~user);
    if (!left) g_ctl_mid = {};
}

void install_server(std::span<const gad::Section> secs) {
    const Addrs& ad = addrs();
    const Check checks[] = {
        {ad.dock_equip, dgl::kDockHead, "the equipment docking spawn's entry"},
        {ad.dock_other, dgl::kDockHead, "the other docking spawn's entry"},
        {ad.dock_call_site, ad.dock_call, "its 2249 caller (call to the equipment docking spawn)"},
        {ad.owner_read, ad.owner_read_bytes, "the field-owner read"},
        {ad.server_execute, dgl::kServerExecuteHead, "ServerGimmick_ExecuteFrameEvent's entry"},
        {ad.server_update, ad.server_update_head, "ServerGimmick_Update's entry"},
    };
    if (!checks_ok(secs, checks)) return;
    std::vector<Prepared> ready;
    if (!prepare(ad.dock_equip, reinterpret_cast<void*>(&dock_detour), dgl::kDockHead,
                 "the equipment docking spawn", g_dock_hook, ready) ||
        !prepare(ad.dock_other, reinterpret_cast<void*>(&dock2_detour), dgl::kDockHead,
                 "the other docking spawn", g_dock2_hook, ready) ||
        !prepare(ad.server_execute, reinterpret_cast<void*>(&exec_detour), dgl::kServerExecuteHead,
                 "ServerGimmick_ExecuteFrameEvent", g_exec_hook, ready) ||
        !prepare(ad.server_update, reinterpret_cast<void*>(&upd_detour), ad.server_update_head,
                 "ServerGimmick_Update", g_upd_hook, ready)) {
        return;
    }
    // The controller's write first (a mid hook, read only here; shared with user2_npc_control, one install): without
    // it the docking context says nothing.
    if (!ctl_write_acquire(kCtlUserDocked, "DockedGimmicks")) {
        return;  // the prepared inline hooks are destroyed disabled: nothing written
    }
    if (!enable_all(ready, "server")) {
        ctl_write_release(kCtlUserDocked);
        return;
    }
    g_server_hooks.store(true);
    log::info("DockedGimmicks: server probe hooked: entries of exe+0x{:X} / exe+0x{:X} (the docking spawns), exe+0x{:X} / "
              "exe+0x{:X} (the server's gimmick event / update: accepted or rejected) and a mid hook at exe+0x{:X} (the "
              "controller written at creation); log only, nothing of the game is written",
              ad.dock_equip, ad.dock_other, ad.server_execute, ad.server_update, ad.ctl_write);
}

bool build_ok() {
    const game::Build b = game::current_build();
    // 3663: only while its 2005 payload is 3527's (game::wire_build(), the record layout kAddrs3663 uses).
    return g_base == g2976::kImageBase &&
           (b == game::Build::v2976 || b == game::Build::v3527 || b == game::Build::v3576 ||
            (b == game::Build::v3663 && game::wire_build() == game::Build::v3527));
}

// ---------------------------------------------------------------- the module's thread

bool is_own_player(uint32_t key) {
    if (!dgl::player_key(key)) return false;
    if (g_guest.load() && g_own_key.load()) return key == g_own_key.load();
    const auto actor = game::find_actor(key);
    const auto ctl = actor ? game::read<uint8_t>(*actor + dgl::kActor_Control) : std::nullopt;
    return ctl && *ctl != 0;
}
std::string hash_text(uint32_t h) {
    const auto ev = rpb::dev_event(h);
    return ev ? std::format("0x{:08X} ({})", h, rpb::dev_event_name(*ev)) : std::format("0x{:08X}", h);
}

struct PendingCheck {
    uint32_t key = 0, parent = 0, controller = 0, written = 0;
    uint64_t due_ms = 0;
    int tries = 0;
};

struct State {
    std::vector<PendingCheck> checks;
    std::map<uint32_t, uint32_t> docked_parent;  // player-docked gimmick key -> parent (from the 2005s)
    uint64_t checks_match = 0, checks_mismatch = 0, checks_not_found = 0;
    // guest_gimmick_interact's trace: the player's position (world x / z, each tick) and the dedupe.
    bool have_pos = false;
    float px = 0, pz = 0;
    gil::Seen<512> gi_pairs;   // (event hash, caller)
    gil::Seen<2048> gi_near;   // (gimmick key, event hash) within kGiNearM of the player
    uint64_t gi_lines = 0;
};
constexpr float kGiNearM = 6.0f;
constexpr uint64_t kGiLines = 800;

// A gimmick's type and world position (x / z), read on the worker thread: the actor may be gone (guarded reads).
struct GiActor {
    uint8_t type = 0;
    bool pos = false;
    float x = 0, z = 0;
};
GiActor gi_actor(uintptr_t a) noexcept {
    GiActor g;
    if (!a) return g;
    if (const auto ti = game::fast_ptr(a + dgl::kActor_TypeInfo)) {
        if (const auto t = game::fast<uint8_t>(*ti + 1)) g.type = *t;
    }
    const auto comps = game::fast_ptr(a + dgl::kActor_Comps);
    const auto ts = comps ? game::fast_ptr(*comps + 0x1A0) : std::nullopt;
    if (!ts) return g;
    const auto x = game::fast<float>(*ts + 0xB4), z = game::fast<float>(*ts + 0xBC);
    const auto sx = game::fast<int16_t>(*ts + 0xC0), sz = game::fast<int16_t>(*ts + 0xC2);
    if (!x || !z || !sx || !sz || !std::isfinite(*x) || !std::isfinite(*z)) return g;
    g.pos = true;
    g.x = *x + *sx * 1000.0f;
    g.z = *z + *sz * 1000.0f;
    return g;
}

uint64_t g_priority_lines = 0;  // the worker's thread only
void log_event(const p8p::Event& e, State& st, uint64_t& lines, uint64_t& not_logged) {
    const auto may_log = [&] {
        if (lines++ < kEventLines) return true;
        ++not_logged;
        return false;
    };
    const auto may_log_priority = [&] {
        if (g_priority_lines++ < kPriorityLines) return true;
        ++not_logged;
        return false;
    };
    const auto seq = static_cast<uint32_t>(e.v[11]);
    switch (e.kind) {
        case kEvDocked: {
            const auto key = static_cast<uint32_t>(e.v[0]);
            const auto parent = static_cast<uint32_t>(e.v[0] >> 32);
            const auto ctl = static_cast<uint32_t>(e.v[1]);
            const auto written = static_cast<uint32_t>(e.v[1] >> 32);
            dgl::Docked dd;
            dd.action = static_cast<dgl::Action>(e.v[2] & 0xFF);
            dd.other = ((e.v[2] >> 9) & 1) != 0;
            const auto action = dd.action;
            const bool host = ((e.v[2] >> 8) & 1) != 0;
            const bool known = st.docked_parent.contains(key);
            st.docked_parent[key] = parent;
            if (!known && st.checks.size() < 256) {
                st.checks.push_back({key, parent, ctl, written, GetTickCount64() + kCheckDelayMs, 0});
            }
            const bool priority =
                action == dgl::Action::Rewritten || (dd.other && action == dgl::Action::WouldRewrite);
            if ((!known || priority) && (priority ? may_log_priority() : may_log())) {
                char name[dgl::kNameChars + 1] = {};
                std::memcpy(name, &e.v[3], dgl::kNameChars);
                log::info("DockedGimmicks #{} 2005 {} {}: gimmick 0x{:08X} '{}' docked to character 0x{:08X} | "
                          "controller +0x12 0x{:08X}{} | {}",
                          seq, host ? "seen by the host's client" : "into this client", p8_when(e.qpc_us), key,
                          name, parent, ctl,
                          written != ctl ? std::format(" -> 0x{:08X}", written) : std::string(),
                          dgl::docked_action_name(dd));
            }
            return;
        }
        case kEvLearnedUser:
            if (may_log()) {
                log::info("DockedGimmicks #{} own user learned {}: character 0x{:08X} is controlled by user 0x{:08X} "
                          "(its 2005 record +0x12)",
                          seq, p8_when(e.qpc_us), static_cast<uint32_t>(e.v[0]), static_cast<uint32_t>(e.v[0] >> 32));
            }
            return;
        case kEvOwnKey:
            if (may_log()) {
                log::info("DockedGimmicks #{} own character {}: 0x{:08X} (MainPlayerDataStartAck 2756); the own user "
                          "and the local-only keys start again",
                          seq, p8_when(e.qpc_us), static_cast<uint32_t>(e.v[0]));
            }
            return;
        case kEvClientFirst:
        case kEvClientRefused: {
            const auto key = static_cast<uint32_t>(e.v[0]);
            const auto parent = static_cast<uint32_t>(e.v[0] >> 32);
            const dgl::Class cls = dgl::classify(parent, is_own_player);
            // World / NPC gimmicks: thousands; counted in the summary only. Player-docked ones: every first / new.
            if (cls != dgl::Class::DockedOwn && cls != dgl::Class::DockedOtherPlayer) return;
            if (!may_log()) return;
            log::info("DockedGimmicks #{} client request {} {}: gimmick 0x{:08X} {} (comp+0x2B4 0x{:08X}) | event {} | "
                      "{} | {} | thread {}",
                      seq, (e.v[1] >> 32) ? "0x8E5F60" : "0x8E59D0", p8_when(e.qpc_us), key, dgl::class_name(cls), parent,
                      hash_text(static_cast<uint32_t>(e.v[1])),
                      e.v[2] ? "REFUSED (eErrNoActorNotExist: not this client's to control)" : "accepted here",
                      e.kind == kEvClientFirst ? "first request seen for it" : "a new refused event", e.tid);
            return;
        }
        case kEvGiTrace: {
            const auto key = static_cast<uint32_t>(e.v[0]);
            const int fn = static_cast<int>((e.v[0] >> 32) & 1);
            const bool let = ((e.v[0] >> 33) & 1) != 0;
            const auto hash = static_cast<uint32_t>(e.v[1]);
            const auto caller = static_cast<uint32_t>(e.v[1] >> 32);
            const GiActor ga = gi_actor(static_cast<uintptr_t>(e.v[2]));
            const float d = st.have_pos && ga.pos ? std::hypot(ga.x - st.px, ga.z - st.pz) : -1.0f;
            const bool is_near = d >= 0 && d <= kGiNearM;
            const uint32_t pair_seen = st.gi_pairs.note(gil::pair_key(hash, caller ^ (fn ? 0x80000000u : 0)));
            const uint32_t near_seen = is_near ? st.gi_near.note(gil::pair_key(key, hash)) : gil::Seen<2048>::kFull;
            const bool show = let ? near_seen < 3 || pair_seen < 3 : pair_seen < 2 || near_seen < 2;
            if (!show) return;
            if (st.gi_lines++ >= kGiLines) {
                g_gi_lines_dropped.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            log::info("GimmickInteract #{} {}: gimmick 0x{:08X} type {} controller 0x{:08X} | {} | event {} | caller "
                      "exe+0x{:X} | {} | {} | thread {}",
                      seq, p8_when(e.qpc_us), key, ga.type, static_cast<uint32_t>(e.v[3]),
                      fn ? "0x9D0B00" : "0x9D05D0", hash_text(hash), caller,
                      let ? "LET THROUGH (guest_gimmick_interact=1)" : "refused (the host controls it)",
                      d < 0 ? std::string("distance unknown") : std::format("{:.1f} m from the player{}", d, is_near ? " (near)" : ""),
                      e.tid);
            return;
        }
        case kEvDockEntry:
            if (may_log()) {
                log::info("DockedGimmicks #{} server docking spawn {} {}: for character 0x{:08X} (type {}, controller "
                          "0x{:08X}) created {} actor(s)",
                          seq, (e.v[1] >> 8) & 0xFF ? "0x28ADE40" : "0x28AD170", p8_when(e.qpc_us),
                          static_cast<uint32_t>(e.v[0]), e.v[1] & 0xFF, static_cast<uint32_t>(e.v[0] >> 32), e.v[2]);
            }
            return;
        case kEvDockCreate:
            if (may_log()) {
                const auto eax = static_cast<uint32_t>(e.v[1]);
                const auto owner = static_cast<uint32_t>(e.v[1] >> 32);
                const auto parent_ctl = static_cast<uint32_t>(e.v[3]);
                log::info("DockedGimmicks #{} server created 0x{:08X} (type {}) inside the docking spawn for 0x{:08X} "
                          "{}: controller written 0x{:08X} (field owner [r13+0x180] 0x{:08X}{}) | the character's "
                          "controller 0x{:08X}{}",
                          seq, static_cast<uint32_t>(e.v[0]), e.v[0] >> 32, static_cast<uint32_t>(e.v[2]),
                          p8_when(e.qpc_us), eax, owner, eax == owner ? ", the field owner" : ", NOT the field owner",
                          parent_ctl,
                          parent_ctl != eax ? " -> phase 2 would write the character's controller here" : "");
            }
            return;
        case kEvServerReject:
            if (may_log()) {
                const auto key = static_cast<uint32_t>(e.v[0]);
                const auto it = st.docked_parent.find(key);
                log::info("DockedGimmicks #{} server REJECTED {} {}: gimmick 0x{:08X}{} controller 0x{:08X}, requester "
                          "user 0x{:08X} | event {} (first rejection for this gimmick)",
                          seq, e.v[2] ? "2758 Update (0x2AC0790)" : "3082 ExecuteFrameEvent (0x2AC1270)",
                          p8_when(e.qpc_us), key,
                          it != st.docked_parent.end() ? std::format(" (docked to 0x{:08X})", it->second) : std::string(),
                          static_cast<uint32_t>(e.v[0] >> 32), static_cast<uint32_t>(e.v[1]),
                          hash_text(static_cast<uint32_t>(e.v[1] >> 32)));
            }
            return;
        case kEvUnspawn:
            if (may_log()) {
                const auto other_age = static_cast<int64_t>(e.v[1]);
                log::info("DockedGimmicks #{} 2221 unspawn from {} {}: gimmick 0x{:08X} | the OTHER user's last "
                          "request for it {} | the requester's own last {}",
                          seq, (e.v[0] >> 32) ? "user 2" : "the host", p8_when(e.qpc_us), static_cast<uint32_t>(e.v[0]),
                          other_age < 0 ? std::string("never") : std::format("{} ms ago", other_age),
                          static_cast<int64_t>(e.v[2]) < 0 ? std::string("never")
                                                           : std::format("{} ms ago", static_cast<int64_t>(e.v[2])));
            }
            return;
        case kEvWithheld:
            if (may_log_priority()) {
                log::info("DockedGimmicks #{} {} {}: request {} of local-only gimmick 0x{:08X}{} (first for this "
                          "gimmick and request){}",
                          seq, (e.v[1] & 1) ? "WITHHELD (never sent to the host)" : "would withhold (probe; sent)",
                          p8_when(e.qpc_us), e.v[0] >> 32, static_cast<uint32_t>(e.v[0]),
                          (e.v[1] & 2) ? std::format(" docked to the OTHER player's character 0x{:08X}", e.v[2])
                                       : std::string(),
                          (e.v[1] & 1) ? " | this PC's capture and the G2 'out' counts still show it: they see the "
                                         "client's PostPacket, before guest_send withholds it; the proof is the host's 'user 2 "
                                   "listed' counter"
                                 : "");
            }
            return;
        case kEvUser2Host: {
            const auto op = static_cast<uint32_t>(e.v[0] & 0xFFFF);
            const auto which = static_cast<uint32_t>((e.v[0] >> 16) & 0xFF);
            const auto at = static_cast<uint32_t>((e.v[0] >> 24) & 0xFF);
            log::info("DockedGimmicks #{} user 2 request {} naming the host's {} 0x{:08X} at +{} {} (#{} of this "
                      "opcode; first {} per opcode logged; review M1: must not grow from step 1 to step 2)",
                      seq, op, which ? "CHARACTER" : "DEVICE (a gimmick docked to its character)",
                      static_cast<uint32_t>(e.v[1]), at, p8_when(e.qpc_us), e.v[2], kUser2HostLinesPerOp);
            return;
        }
        case kEvUser2Listed:
            if (may_log()) {
                const auto parent = static_cast<uint32_t>(e.v[1]);
                log::info("DockedGimmicks #{} user 2 SENT request {} for gimmick 0x{:08X} docked to 0x{:08X} ({}) {} "
                          "(at the server's receive; first {} logged)",
                          seq, e.v[0] >> 32, static_cast<uint32_t>(e.v[0]), parent, e.v[2] == 0   ? "user 2's own"
                                                                                      : e.v[2] == 1 ? "the host's"
                                                                                                    : "host's own unknown",
                          p8_when(e.qpc_us), kUser2ListedLines);
            }
            return;
        case kEvRetired:
            if (may_log_priority()) {
                log::info("DockedGimmicks #{} local-only key 0x{:08X} dropped {} ({})", seq,
                          static_cast<uint32_t>(e.v[0]), p8_when(e.qpc_us),
                          e.v[1] ? "RemoveActorAck 2516" : "a 2005 announced it with another parent or not docked");
            }
            return;
        case kEvMalformed:
            if (may_log()) {
                log::warn("DockedGimmicks #{} a 2005 whose record lengths do not add up {} ({} records read): the "
                          "records before the bad one were classified, nothing after",
                          seq, p8_when(e.qpc_us), e.v[0]);
            }
            return;
        case kEvDedupGuest: {
            const auto key = static_cast<uint32_t>(e.v[0]);
            const auto ctl = static_cast<uint32_t>(e.v[0] >> 32);
            const auto own = static_cast<uint32_t>(e.v[1]);
            const auto v = static_cast<ged::Verdict>((e.v[1] >> 32) & 0xFF);
            const char* action = e.v[2] == 2 ? "WITHHELD (never sent to the host)"
                                 : e.v[2] == 1 ? "would withhold (probe; sent)"
                                               : "sent";
            {  // at most kDedupGuestLines events are pushed: no shared budget
                log::info("GimmickEventDedup [{}] #{} 2779 for gimmick 0x{:08X} {}: controller (last 2005 +0x12) {} | "
                          "own user 0x{:08X} | {} -> {}",
                          dgl::mode_name(dedup_mode()), seq, key, p8_when(e.qpc_us),
                          ctl ? std::format("0x{:08X}{}", ctl, ctl == own ? " (this client's)" : " (the other user's)")
                              : std::string("unknown"),
                          own, ged::verdict_name(v), action);
            }
            return;
        }
        case kEvDedupCreated: {
            const auto key = static_cast<uint32_t>(e.v[0]);
            const auto index = static_cast<uint32_t>(e.v[0] >> 32);
            const auto kind = static_cast<ged::Created>(e.v[1] & 0xFF);
            const int trigger = static_cast<int>(static_cast<int8_t>((e.v[1] >> 8) & 0xFF));
            {  // at most kDedupHostLines events are pushed: no shared budget
                log::info("GimmickEventDedup host #{} 2250 for gimmick 0x{:08X} index {} {}: {} | last 2779 within {} "
                          "ms: {} | 2779 so far: the host's client {}, user 2 {}",
                          seq, key, index, p8_when(e.qpc_us), ged::created_name(kind), ged::kDupWindowMs,
                          trigger < 0 ? std::string("none")
                                      : std::format("{} ({} ms before)", trigger ? "user 2's" : "the host's client's",
                                                    e.v[2]),
                          static_cast<uint32_t>(e.v[3]), static_cast<uint32_t>(e.v[3] >> 32));
            }
            return;
        }
        default: return;
    }
}

void run_checks(State& st, uint64_t now, uint64_t& lines, uint64_t& not_logged) {
    for (auto it = st.checks.begin(); it != st.checks.end();) {
        if (now < it->due_ms) {
            ++it;
            continue;
        }
        const auto actor = game::find_actor(it->key);
        if (!actor) {
            if (++it->tries >= kCheckTries) {
                ++st.checks_not_found;
                it = st.checks.erase(it);
            } else {
                it->due_ms = now + kCheckDelayMs;
                ++it;
            }
            continue;
        }
        const auto ctl = game::read<uint32_t>(*actor + dgl::kActor_Controller);
        const auto comps = game::read_ptr(*actor + dgl::kActor_Comps);
        const auto comp = comps ? game::read_ptr(*comps + dgl::kComps_Gimmick) : std::nullopt;
        const bool vt_ok = comp && game::has_vtable(*comp, g_base + addrs().client_vtbl);
        const auto parent = vt_ok ? game::read<uint32_t>(*comp + dgl::kComp_DockParent) : std::nullopt;
        // P8 S29: only +0x90 is compared. +0x2B4 is not the docked parent (0 in 80 / 80 S28 checks on both PCs,
        // also for natively controlled devices); it stays in the line for information.
        const bool match = ctl && *ctl == it->written;
        (match ? st.checks_match : st.checks_mismatch) += 1;
        if (lines++ < kEventLines) {
            log::info("DockedGimmicks check of 0x{:08X}: client actor +0x90 {} (the 2005 had 0x{:08X}{}) | "
                      "pa::ClientGimmickActorComponent {} +0x2B4 {} (not compared; the 2005's parent 0x{:08X}) -> {}",
                      it->key, ctl ? std::format("0x{:08X}", *ctl) : std::string("unreadable"), it->controller,
                      it->written != it->controller ? std::format(", written 0x{:08X}", it->written) : std::string(),
                      vt_ok ? "found" : "NOT found (vtable)",
                      parent ? std::format("0x{:08X}", *parent) : std::string("unread"), it->parent,
                      match ? "MATCH" : "DIFFERENT");
        } else {
            ++not_logged;
        }
        it = st.checks.erase(it);
    }
}

// gimmick_event_dedup, host (P8 S29): the keys user 2 sent a 2779 for and the host's client never did (the far case
// that decides mode 1 on the guest), one line each (the worker thread; at most kLoneLines), with where the players
// and the gimmick are on the host's client at that moment (~5 s after user 2's last 2779 for it).
constexpr size_t kLoneLines = 64;
std::set<uint32_t> g_lone_logged;  // the worker thread only
std::string where_text(uint32_t key) {
    const auto p = key ? game::actor_world_position(key) : std::nullopt;
    return p ? std::format("({:.1f}, {:.1f}, {:.1f})", p->x, p->y, p->z) : std::string("not found on this client");
}
void scan_lone(uint64_t now) {
    if (dedup_mode() == dgl::Mode::Off || g_guest.load() || g_lone_logged.size() >= kLoneLines) return;
    for (size_t i = 0; i < g_dup.size() && g_lone_logged.size() < kLoneLines; ++i) {
        const ged::DupEntry& e = g_dup.at(i);
        const uint32_t key = e.key.load(std::memory_order_relaxed);
        if (!key || g_lone_logged.contains(key)) continue;
        const uint32_t cnt[2] = {e.count_2779[0].load(std::memory_order_relaxed),
                                 e.count_2779[1].load(std::memory_order_relaxed)};
        if (!ged::lone_user2(cnt, e.last_2779[1].load(std::memory_order_relaxed), now)) continue;
        g_lone_logged.insert(key);
        const uint32_t host_char = g_host_own_key.load(), u2_char = g_host_user2_char.load();
        const auto hp = host_char ? game::actor_world_position(host_char) : std::nullopt;
        const auto up = u2_char ? game::actor_world_position(u2_char) : std::nullopt;
        std::string dist = "unknown";
        if (hp && up) {
            const float dx = hp->x - up->x, dy = hp->y - up->y, dz = hp->z - up->z;
            dist = std::format("{:.1f} m", std::sqrt(dx * dx + dy * dy + dz * dz));
        }
        log::info("GimmickEventDedup host: 2779 of user 2 for gimmick 0x{:08X} that the host's client never sent a "
                  "2779 for ({} from user 2, {} ms after its last; 2250 for the key so far {}) | distance between "
                  "the players {} (host 0x{:08X} {}, user 2 0x{:08X} {}) | the gimmick on the host's client {} | "
                  "with the guest at gimmick_event_dedup=1 this 2779 would be withheld and its projectile lost",
                  key, cnt[1], now - e.last_2779[1].load(std::memory_order_relaxed),
                  e.created.load(std::memory_order_relaxed), dist, host_char, where_text(host_char), u2_char,
                  where_text(u2_char), where_text(key));
    }
}

void log_dedup_summary() {
    if (dedup_mode() == dgl::Mode::Off) return;
    if (g_guest.load()) {
        std::string v;
        for (size_t i = 0; i < static_cast<size_t>(ged::Verdict::Count); ++i) {
            const uint64_t a = g_ged_guest[i][0].load(), b = g_ged_guest[i][1].load(), c = g_ged_guest[i][2].load();
            if (a || b || c) {
                v += std::format("{}{}: sent {}, would withhold {}, WITHHELD {}", v.empty() ? "" : " | ",
                                 ged::verdict_name(static_cast<ged::Verdict>(i)), a, b, c);
            }
        }
        log::info("GimmickEventDedup summary (guest, gimmick_event_dedup={}): outgoing 2779: {} | own user 0x{:08X} | "
                  "controllers known {} (table full {})",
                  dgl::mode_name(dedup_mode()), v.empty() ? std::string("none yet") : v, g_own_user.load(),
                  g_ctl_map.used(), g_ctl_map.full());
        return;
    }
    // Host: the keys whose last 2779 got no 2250 within the window (a withheld 2779 whose projectile never came would
    // show here as a 2779 of the HOST's client without a projectile).
    const uint64_t now = GetTickCount64();
    uint64_t no_projectile[2] = {}, lone_keys = 0, lone_2779 = 0;
    for (size_t i = 0; i < g_dup.size(); ++i) {
        const ged::DupEntry& e = g_dup.at(i);
        if (!e.key.load(std::memory_order_relaxed)) continue;
        const uint32_t cnt[2] = {e.count_2779[0].load(std::memory_order_relaxed),
                                 e.count_2779[1].load(std::memory_order_relaxed)};
        if (ged::lone_user2(cnt, e.last_2779[1].load(std::memory_order_relaxed), now)) {
            ++lone_keys;
            lone_2779 += cnt[1];
        }
        const uint64_t c = e.last_2250.load(std::memory_order_relaxed);
        for (int o = 0; o < 2; ++o) {
            const uint64_t t = e.last_2779[o].load(std::memory_order_relaxed);
            if (t && now > t + ged::kDupWindowMs && c < t) ++no_projectile[o];
        }
    }
    log::info("GimmickEventDedup summary (host, gimmick_event_dedup={}, log only): 2779 at the server's receive: the "
              "host's client {}, user 2 {} | 2250 (sniffer): first {}, DUPLICATE created {}, index > 1 without both "
              "{} | keys whose last 2779 got no 2250 within {} ms: the host's client's {}, user 2's {} | 2779 of "
              "user 2 for a key the host's client never sent a 2779 for: keys {}, 2779 {} (the far case; measurable "
              "only while the guest is at probe) | gimmicks {} (full {}, 2779 untracked {}, 2250 untracked {})",
              dgl::mode_name(dedup_mode()), g_ged_2779[0].load(), g_ged_2779[1].load(),
              g_ged_created[static_cast<size_t>(ged::Created::First)].load(),
              g_ged_created[static_cast<size_t>(ged::Created::Duplicate)].load(),
              g_ged_created[static_cast<size_t>(ged::Created::LaterNoBoth)].load(), ged::kDupWindowMs,
              no_projectile[0], no_projectile[1], lone_keys, lone_2779, g_dup.used(), g_dup.full(),
              g_ged_2779_untracked.load(),
              g_ged_2250_untracked.load());
}

void log_summary(State& st, uint64_t not_logged) {
    log_dedup_summary();
    if (mode() == dgl::Mode::Off) return;
    // Client requests per class (the table, read racily: counts only).
    struct Agg {
        uint64_t keys = 0, calls[2] = {}, refused[2] = {};
        std::map<uint32_t, uint64_t> refused_hashes;
    };
    Agg agg[static_cast<size_t>(dgl::Class::Count)];
    std::map<uint32_t, bool> own_cache;
    const auto own = [&](uint32_t k) {
        auto it = own_cache.find(k);
        if (it != own_cache.end()) return it->second;
        const bool v = is_own_player(k);
        own_cache[k] = v;
        return v;
    };
    for (size_t i = 0; i < g_client.size(); ++i) {
        const dgl::ClientEntry& e = g_client.at(i);
        if (!e.key.load(std::memory_order_relaxed)) continue;
        Agg& a = agg[static_cast<size_t>(dgl::classify(e.parent.load(std::memory_order_relaxed), own))];
        ++a.keys;
        for (int f = 0; f < 2; ++f) {
            a.calls[f] += e.calls[f].load(std::memory_order_relaxed);
            a.refused[f] += e.refused[f].load(std::memory_order_relaxed);
        }
        if (e.refused[0].load(std::memory_order_relaxed) + e.refused[1].load(std::memory_order_relaxed)) {
            ++a.refused_hashes[e.last_refused_hash.load(std::memory_order_relaxed)];
        }
    }
    std::string client;
    for (size_t c = 0; c < static_cast<size_t>(dgl::Class::Count); ++c) {
        const Agg& a = agg[c];
        if (!a.keys) continue;
        std::string hashes;
        size_t shown = 0;
        for (const auto& [h, n] : a.refused_hashes) {
            if (shown++ == 4) {
                hashes += " ...";
                break;
            }
            hashes += std::format("{}{} x{}", hashes.empty() ? "" : ", ", hash_text(h), n);
        }
        client += std::format("{}{}: {} gimmicks, 0x8E59D0 {} ({} refused), 0x8E5F60 {} ({} refused){}",
                              client.empty() ? "" : "; ", dgl::class_name(static_cast<dgl::Class>(c)), a.keys,
                              a.calls[0], a.refused[0], a.calls[1], a.refused[1],
                              hashes.empty() ? std::string() : " | refused last events: " + hashes);
    }
    std::string withheld, withheld_other;
    for (size_t i = 0; i < dgl::kWithheldOpCount; ++i) {
        const uint64_t w = g_withheld[0][i].load(), ww = g_would_withhold[0][i].load();
        if (w || ww) withheld += std::format("{}{} {}/{}", withheld.empty() ? "" : ", ", dgl::kWithheldOps[i], w, ww);
        const uint64_t wo = g_withheld[1][i].load(), wwo = g_would_withhold[1][i].load();
        if (wo || wwo) {
            withheld_other +=
                std::format("{}{} {}/{}", withheld_other.empty() ? "" : ", ", dgl::kWithheldOps[i], wo, wwo);
        }
    }
    const bool guest = g_guest.load();
    log::info("DockedGimmicks summary ({}, docked_gimmicks={}): 2005 packets {} records {} gimmicks {} | not docked {}, "
              "docked to NPC/object {}, docked to a player {}: rewritten {}, would rewrite {}, already this client's {}, "
              "another player's {} (docked_gimmicks_other={}: rewritten {}, would rewrite {}, unchanged {}), own user "
              "unknown {}, own character unknown {}, not rewritten: controller not a user {}, name {}, malformed "
              "packet {} | malformed {} | {}local-only keys {} (of them the other player's {}; overwritten {}, retired "
              "{} + {} by 2516) | withheld/would own {} | withheld/would other player {} | resets {} | checks of the "
              "2005 against the client (+0x90 only): match {}, DIFFERENT {}, not found {}",
              guest ? "guest" : "host", dgl::mode_name(mode()), g_c.packets.load(), g_c.records.load(),
              g_c.gimmicks.load(), g_c.not_docked.load(), g_c.docked_world.load(), g_c.docked_player.load(),
              g_c.rewritten.load(), g_c.would_rewrite.load(), g_c.already_mine.load(), g_c.other_player.load(),
              dgl::mode_name(other_mode()), g_c.other_rewritten.load(), g_c.other_would_rewrite.load(),
              g_c.other_unchanged.load(), g_c.own_user_unknown.load(), g_c.own_key_unknown.load(),
              g_c.not_user_controller.load(), g_c.not_game_mechanic.load(), g_c.malformed_not_written.load(),
              g_c.malformed.load(),
              guest ? std::format("own character 0x{:08X} user 0x{:08X} | ", g_own_key.load(), g_own_user.load())
                    : std::string(),
              g_keys.used(), g_keys.used_with(dgl::kKeyOther), g_keys.overwritten(), g_c.retired.load(),
              g_c.retired_2516.load(), withheld.empty() ? std::string("none") : withheld,
              withheld_other.empty() ? std::string("none") : withheld_other, g_resets.load(), st.checks_match,
              st.checks_mismatch, st.checks_not_found);
    log::info("DockedGimmicks summary, client requests (hooks {}): {} | untracked {} (table {} used, full {}) | the "
              "refusal code 0x{:08X} | lines not logged {}, ring dropped {}",
              g_client_hooks.load() ? "on" : "OFF", client.empty() ? std::string("none seen yet") : client,
              g_client_untracked.load(), g_client.used(), g_client.full(), g_err_code.load(), not_logged,
              g_ring.dropped());
    if (gi_mode() != gil::Mode::Off) {
        log::info("GimmickInteract summary (guest_gimmick_interact={}, compares {}): refused {}, let through {} | trace "
                  "lines {} (not logged past the cap {}), (event, caller) pairs {}, near (gimmick, event) pairs {}",
                  gil::mode_name(gi_mode()), g_gi_hooks.load() ? "hooked" : "not hooked", g_gi_refused.load(),
                  g_gi_let.load(), st.gi_lines, g_gi_lines_dropped.load(), st.gi_pairs.used(), st.gi_near.used());
    }
    if (!guest) {
        std::string unspawn;
        for (int u = 0; u < 2; ++u) {
            std::string b;
            for (size_t k = 0; k < dgl::kAgeBuckets; ++k) {
                b += std::format("{}{} {}", b.empty() ? "" : ", ", dgl::age_bucket_name(k), g_unspawn[u][k].load());
            }
            unspawn += std::format("{}from {}: {} requests (2928 spawn requests {}), the OTHER user's last request "
                                   "for the gimmick: {}",
                                   unspawn.empty() ? "" : " | ", u ? "user 2" : "the host", g_unspawn_reqs[u].load(),
                                   g_spawn_reqs[u].load(), b);
        }
        const auto sc = [](int op, int who, int rej) { return g_server_counts[op][who][rej].load(); };
        std::string listed;
        uint64_t listed_own = 0, listed_host = 0;
        for (int c = 0; c < 3; ++c) {
            std::string ops;
            for (size_t i = 0; i < dgl::kWithheldOpCount; ++i) {
                const uint64_t n = g_user2_listed[c][i].load();
                if (c == 0) listed_own += n;
                if (c == 1) listed_host += n;
                if (n) ops += std::format("{}{} x{}", ops.empty() ? "" : ", ", dgl::kWithheldOps[i], n);
            }
            listed += std::format("{}{}: {}", listed.empty() ? "" : " | ",
                                  c == 0 ? "docked to user 2's own character" : c == 1 ? "docked to the host's"
                                                                                       : "host's own unknown",
                                  ops.empty() ? std::string("0") : ops);
        }
        log::info("DockedGimmicks summary, user 2 listed requests at the server's receive (3082 2758 2609 2774 3089 "
                  "2779 2826 2618 for gimmicks docked to a player; its own: 0 with the guest's docked_gimmicks=1; "
                  "the host's: S28 2774 x6 per creation, 0 with the guest's docked_gimmicks_other=1): TOTAL for its "
                  "own {} | TOTAL for the host's {} | {} | host's own character 0x{:08X}",
                  listed_own, listed_host, listed, g_host_own_key.load());
        std::string named[2];
        uint64_t named_total[2] = {};
        for (int w = 0; w < 2; ++w) {
            for (size_t op = 0; op < kOpSlots; ++op) {
                const uint32_t n = g_user2_host[w][op].load(std::memory_order_relaxed);
                if (!n) continue;
                named_total[w] += n;
                named[w] += std::format("{}{} x{}", named[w].empty() ? "" : ", ", op, n);
            }
        }
        log::info("DockedGimmicks summary, user 2 requests of any opcode naming the host's device or character at the "
                  "server's receive (key at +0 or +1; review M1: per opcode, must not grow from step 1 to step 2): "
                  "the host's DEVICE {} ({}; at +1 {}) | the host's CHARACTER {} ({}; at +1 {})",
                  named_total[0], named[0].empty() ? std::string("none") : named[0], g_user2_host_at1[0].load(),
                  named_total[1], named[1].empty() ? std::string("none") : named[1], g_user2_host_at1[1].load());
        log::info("DockedGimmicks summary, server (hooks {}, probe at the receive {}){}: creations inside a docking "
                  "spawn {}, docking spawns 0x28AD170 {} (for players {}) / 0x28ADE40 {} (for players {}), field owner "
                  "0x{:08X} | 3082 accepted/rejected: field owner's client {}/{}, other {}/{} | 2758: field owner's "
                  "{}/{}, other {}/{} | untracked {} | 2221: {} (keys past 16 not measured {}) | keyed requests seen "
                  "{} (table {} used, full {})",
                  g_server_hooks.load() ? "on" : "OFF", g_server_probe.load() ? "on" : "OFF", std::string(),
                  g_creations_in_dock.load(), g_dock_entries[0].load(), g_dock_entries_player[0].load(),
                  g_dock_entries[1].load(), g_dock_entries_player[1].load(), g_field_owner.load(), sc(0, 0, 0),
                  sc(0, 0, 1), sc(0, 1, 0), sc(0, 1, 1), sc(1, 0, 0), sc(1, 0, 1), sc(1, 1, 0), sc(1, 1, 1),
                  g_server_untracked.load(), unspawn, g_unspawn_keys_not_measured.load(), g_touches.load(),
                  g_touch.used(), g_touch.full());
    }
}

DWORD WINAPI worker_thread(LPVOID) {
    try {
        game::PlayerReader reader;
        reader.init();
        uint32_t in_world = 0;
        bool hook_tried = false;
        uint64_t lines = 0, not_logged = 0;
        uint32_t lone_tick = 0;
        uint64_t last_minute = GetTickCount64();
        State st;
        for (;;) {
            Sleep(kTickMs);
            const uint64_t now = GetTickCount64();
            if (!hook_tried) {
                in_world = reader.read() ? in_world + 1 : 0;
                if (in_world >= kWorldTicks) {
                    hook_tried = true;
                    uint32_t code = 0;
                    if (game::safe_read(g_base + addrs().err_global, &code, sizeof code) && code) {
                        if (code != dgl::kErrNotController) {
                            log::warn("DockedGimmicks: the game's eErrNoActorNotExist is 0x{:08X}, not 0x{:08X}; the "
                                      "game's value is used for 'refused'",
                                      code, dgl::kErrNotController);
                        }
                        g_err_code.store(code);
                    }
                    std::vector<gad::Section> secs;
                    if (!p8_exe_sections(g_base, secs)) {
                        log::error("DockedGimmicks: the exe's sections are unreadable; the probe hooks are not in (the "
                                   "packet part goes on)");
                    } else {
                        // The probe hooks are docked_gimmicks' only (gimmick_event_dedup is packets only).
                        if (mode() != dgl::Mode::Off) {
                            install_client(secs);
                            if (!g_guest.load()) install_server(secs);
                        }
                    }
                    last_minute = now;
                }
            }
            if (hook_tried && gi_mode() != gil::Mode::Off) {
                if (const auto s = reader.read()) {
                    st.have_pos = true;
                    st.px = s->position.x;
                    st.pz = s->position.z;
                }
            }
            p8p::Event e;
            while (g_ring.pop(e)) log_event(e, st, lines, not_logged);
            if (hook_tried) run_checks(st, now, lines, not_logged);
            if (hook_tried && (++lone_tick & 3) == 0) scan_lone(now);
            if (hook_tried && now - last_minute >= kMinuteMs) {
                last_minute = now;
                log_summary(st, not_logged);
            }
        }
    } catch (...) {
        log::error("DockedGimmicks: the worker stopped (exception); nothing more is logged (the hooks and the packet "
                   "part stay as they are)");
    }
    return 0;
}

}  // namespace

// ---------------------------------------------------------------- guest: packets

void docked_gimmicks_guest_reset(const char* why) noexcept {
    (void)why;
    if (!any_mode() || !g_guest.load(std::memory_order_relaxed)) return;
    g_ctl_map.clear();  // gimmick_event_dedup: keys are per world
    // The character key repeats across worlds (0xA0100377 in the guest's own world and in the host's): the own
    // character and its user are learned again from the next conversation's 2756 and 2005.
    g_own_key.store(0);
    g_own_user.store(0);
    g_keys.clear();
    g_docked_map.clear();  // the client probe's classes: keys are per world too
    g_resets.fetch_add(1, std::memory_order_relaxed);
}

void docked_gimmicks_guest_deliver(std::vector<uint8_t>& packet) noexcept {
    const dgl::Mode m = mode();
    const dgl::Mode dm = dedup_mode();
    if ((m == dgl::Mode::Off && dm == dgl::Mode::Off) || !g_guest.load(std::memory_order_relaxed) ||
        packet.size() < dgl::kHeader) {
        return;
    }
    try {
        const uint16_t op = dgl::le16(packet.data());
        const size_t len = std::min<size_t>(dgl::le16(packet.data() + 3), packet.size() - dgl::kHeader);
        const std::span<const uint8_t> body(packet.data() + dgl::kHeader, len);
        if (op == dgl::kOpMainPlayerDataStart) {
            // The own character, in order with the 2005s and on their thread (MainPlayerDataStartAck, u32 at +0).
            // P8 S29: every 2756 starts a world (S28: two per guest run, one per world entry, none at a revive), so
            // the user and the local-only keys start again even when the character key repeats (S28 step 1: the
            // guest's own world reused 0xA0100001 and the gimmick keys 0xB010013F-44 of the host's world).
            if (body.size() >= 4) {
                const uint32_t key = dgl::le32(body.data());
                if (key) {
                    g_own_key.store(key);
                    g_own_user.store(0);
                    g_keys.clear();
                    g_docked_map.clear();
                    push(kEvOwnKey, key);
                }
            }
            return;
        }
        if (op == dgl::kOpRemoveActor) {
            uint32_t keys[8] = {};
            const size_t n = dgl::removed_keys(body, keys, std::size(keys));
            for (size_t i = 0; i < n; ++i) {
                if (g_keys.remove(keys[i])) {
                    g_c.retired_2516.fetch_add(1, std::memory_order_relaxed);
                    push(kEvRetired, keys[i], 1);
                }
            }
            return;
        }
        const std::span<uint8_t> pl = dgl::payload_2005(packet);
        if (pl.empty()) return;
        dgl::Self self{g_own_key.load(), g_own_user.load()};
        if (dm != dgl::Mode::Off) {
            // The controllers as the server sent them: before docked_gimmicks rewrites anything.
            (void)ged::record_controllers(pl, g_ctl_map);
            if (m == dgl::Mode::Off) {
                if (const uint32_t u = dgl::learn_own_user(pl, self)) {
                    g_own_user.store(u);
                    push(kEvLearnedUser, self.own_key | (uint64_t{u} << 32));
                }
                return;
            }
        }
        const dgl::Result2005 r = dgl::process_2005(pl, self, m, g_keys, other_mode(), addrs().rec);
        if (r.learned_user) {
            g_own_user.store(r.learned_user);
            push(kEvLearnedUser, self.own_key | (uint64_t{r.learned_user} << 32));
        }
        count(r);
        push_docked(r, /*host=*/false);
    } catch (...) {
        g_c.faults.fetch_add(1, std::memory_order_relaxed);
    }
}

bool docked_gimmicks_guest_withhold(const uint8_t* packet, size_t size) noexcept {
    const dgl::Mode m = mode();
    const dgl::Mode dm = dedup_mode();
    if ((m == dgl::Mode::Off && dm == dgl::Mode::Off) || !packet || !g_guest.load(std::memory_order_relaxed)) {
        return false;
    }
    bool docked_withholds = false;
    const int i = m == dgl::Mode::Off ? -1 : dgl::withhold_index(std::span<const uint8_t>(packet, size), g_keys);
    if (i >= 0) {
        // Each key carries its own decision (phase 1 / docked_gimmicks_other, mode 1 or probe).
        const uint32_t key = dgl::le32(packet + dgl::kHeader);
        dgl::LocalKey lk;
        if (g_keys.find(key, lk)) {
            const bool on = (lk.flags & dgl::kKeyOn) != 0;
            const int other = (lk.flags & dgl::kKeyOther) ? 1 : 0;
            (on ? g_withheld[other][i] : g_would_withhold[other][i]).fetch_add(1, std::memory_order_relaxed);
            if (first_withheld(key, dgl::kWithheldOps[i])) {
                push(kEvWithheld, key | (uint64_t{dgl::kWithheldOps[i]} << 32),
                     (on ? 1u : 0u) | (other ? 2u : 0u), lk.parent);
            }
            docked_withholds = on;
        }
    }
    // gimmick_event_dedup: every 2779 decided against the controller the server sent (never counted twice: when
    // docked_gimmicks' own-key rule withholds it, the line says that rule matched).
    if (dm != dgl::Mode::Off && size >= dgl::kHeader + 4 && dgl::le16(packet) == ged::kOpCreateFromGimmickEvent) {
        const uint32_t key = dgl::le32(packet + dgl::kHeader);
        const ged::CtlEntry* e = g_ctl_map.find(key);
        const uint32_t ctl = e ? e->controller.load(std::memory_order_relaxed) : 0;
        const uint32_t own = g_own_user.load(std::memory_order_relaxed);
        const ged::Verdict v = docked_withholds ? ged::Verdict::DockedRule : ged::decide(ctl, own);
        const int action = v != ged::Verdict::WouldWithhold ? 0 : dm == dgl::Mode::On ? 2 : 1;
        g_ged_guest[static_cast<size_t>(v)][action].fetch_add(1, std::memory_order_relaxed);
        if (g_ged_guest_lines.fetch_add(1, std::memory_order_relaxed) < kDedupGuestLines) {
            push(kEvDedupGuest, key | (uint64_t{ctl} << 32), own | (uint64_t(v) << 32), static_cast<uint64_t>(action));
        }
        if (action == 2) return true;
    }
    return docked_withholds;
}

// ---------------------------------------------------------------- host: the sniffer and the server's receive

void docked_gimmicks_sniffed(const uint8_t* packet, size_t size, uint64_t, bool server_to_client) noexcept {
    if (!any_mode() || g_guest.load(std::memory_order_relaxed) || !packet || size < dgl::kHeader) return;
    const uint16_t op = dgl::le16(packet);
    // gimmick_event_dedup (host, log only): each 2250 of the host's client against the 2779 the server received.
    if (server_to_client && op == ged::kOpCreateProjectileAck && dedup_mode() != dgl::Mode::Off) {
        const ged::Ack2250 a = ged::parse_2250(std::span<const uint8_t>(packet + dgl::kHeader, size - dgl::kHeader));
        if (!a.owner) return;
        ged::DupEntry* e = g_dup.find(a.owner) ? g_dup.get(a.owner) : nullptr;  // only gimmicks a 2779 named
        if (!e) {
            if (a.index > 1) g_ged_2250_untracked.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        const uint64_t now = GetTickCount64();
        const uint64_t last[2] = {e->last_2779[0].load(std::memory_order_relaxed),
                                  e->last_2779[1].load(std::memory_order_relaxed)};
        const uint32_t cnt[2] = {e->count_2779[0].load(std::memory_order_relaxed),
                                 e->count_2779[1].load(std::memory_order_relaxed)};
        const ged::CreatedVerdict v = ged::classify_2250(a.index, now, last, cnt);
        e->last_2250.store(now, std::memory_order_relaxed);
        e->created.fetch_add(1, std::memory_order_relaxed);
        if (v.kind == ged::Created::Duplicate) e->duplicates.fetch_add(1, std::memory_order_relaxed);
        g_ged_created[static_cast<size_t>(v.kind)].fetch_add(1, std::memory_order_relaxed);
        if (v.kind != ged::Created::First && g_ged_host_lines.fetch_add(1, std::memory_order_relaxed) < kDedupHostLines) {
            push(kEvDedupCreated, a.owner | (uint64_t{a.index} << 32),
                 static_cast<uint64_t>(v.kind) | (static_cast<uint64_t>(static_cast<uint8_t>(v.trigger)) << 8),
                 v.gap_ms, cnt[0] | (uint64_t{cnt[1]} << 32));
        }
        return;
    }
    if (mode() == dgl::Mode::Off) return;
    if (!server_to_client || (op != dgl::kOpActorLoad && op != dgl::kOpMainPlayerDataStart)) return;
    try {
        // The host's client is never changed: a copy, classified in probe whatever the mode (phase 1 is a no-op
        // here: the field owner already controls its own character's docked gimmicks, user 2's are never taken).
        static dgl::Self t_self;  // the sniffer's writer thread only
        static dgl::LocalKeys t_keys;
        if (op == dgl::kOpMainPlayerDataStart) {
            if (size >= dgl::kHeader + 4) {
                const uint32_t k = dgl::le32(packet + dgl::kHeader);
                if (k && k != t_self.own_key) {
                    t_self = dgl::Self{k, 0};
                    g_host_own_key.store(k, std::memory_order_relaxed);
                    push(kEvOwnKey, k);
                }
            }
            return;
        }
        std::vector<uint8_t> copy(packet, packet + size);
        const std::span<uint8_t> pl = dgl::payload_2005(copy);
        if (pl.empty()) return;
        const dgl::Result2005 r = dgl::process_2005(pl, t_self, dgl::Mode::Probe, t_keys, dgl::Mode::Off, addrs().rec);
        if (r.learned_user) push(kEvLearnedUser, t_self.own_key | (uint64_t{r.learned_user} << 32));
        count(r);
        push_docked(r, /*host=*/true);
    } catch (...) {
        g_c.faults.fetch_add(1, std::memory_order_relaxed);
    }
}

bool docked_gimmicks_ctl_write_for_user2(const char* who) noexcept {
    try {
        // 3527 / 3576 / 3663: user2_npc_control is not ported; only docked_gimmicks' read-only use of the hook is
        // verified there.
        const game::Build b = game::current_build();
        if (b == game::Build::v3527 || b == game::Build::v3576 || b == game::Build::v3663) {
            log::warn("{}: user2_npc_control's use of the server's controller write is not ported to 1.0.0.{}; REFUSED",
                      who, b == game::Build::v3663 ? 3663 : b == game::Build::v3576 ? 3576 : 3527);
            return false;
        }
        return ctl_write_acquire(kCtlUserU2, who);
    } catch (...) {
        return false;
    }
}

void docked_gimmicks_server_ingress(uint16_t op, uintptr_t packet, uint16_t size, bool from_user2) noexcept {
    if (!g_server_probe.load(std::memory_order_relaxed) || !packet || size < dgl::kHeader + 4) return;
    const int who = from_user2 ? 1 : 0;
    // gimmick_event_dedup (host, log only): every 2779 the server receives, by origin and gimmick.
    if (op == ged::kOpCreateFromGimmickEvent && dedup_mode() != dgl::Mode::Off) {
        g_ged_2779[who].fetch_add(1, std::memory_order_relaxed);
        if (const auto key = game::fast<uint32_t>(packet + dgl::kHeader)) {
            if (ged::DupEntry* e = g_dup.get(*key)) {
                e->last_2779[who].store(GetTickCount64(), std::memory_order_relaxed);
                e->count_2779[who].fetch_add(1, std::memory_order_relaxed);
            } else {
                g_ged_2779_untracked.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }
    if (mode() == dgl::Mode::Off) return;
    // Review M1: user 2's requests of any opcode naming the host's device or character (+0, or +1 after a u8 prefix).
    if (from_user2 && op < kOpSlots) {
        const uint32_t host_key = g_host_own_key.load(std::memory_order_relaxed);
        uint8_t head[5] = {};
        const size_t have = std::min<size_t>(sizeof head, size - dgl::kHeader);  // >= 4 (checked at the entry)
        if (host_key && game::fast_read(packet + dgl::kHeader, head, have)) {
            for (uint32_t at = 0; at + 4 <= have && at < 2; ++at) {
                const uint32_t k = dgl::le32(head + at);
                int which = -1;
                if (k == host_key) {
                    which = 1;
                } else if (dgl::world_key(k) && g_docked_map.parent_of(k) == host_key) {
                    which = 0;
                }
                if (which < 0) continue;
                const uint32_t n = g_user2_host[which][op].fetch_add(1, std::memory_order_relaxed) + 1;
                if (at) g_user2_host_at1[which].fetch_add(1, std::memory_order_relaxed);
                if (n <= kUser2HostLinesPerOp &&
                    g_user2_host_lines.fetch_add(1, std::memory_order_relaxed) < kUser2HostLines) {
                    push(kEvUser2Host, op | (uint64_t(which) << 16) | (uint64_t{at} << 24), k, n);
                }
                break;
            }
        }
    }
    // User 2's listed state requests for a gimmick docked to a player (item 1 of the S28 review): the proof that the
    // guest's withholding works is here, not in the guest's own capture (its sniffer sees PostPacket, before it).
    if (from_user2) {
        if (const int i = dgl::withheld_op_index(op); i >= 0) {
            if (const auto key = game::fast<uint32_t>(packet + dgl::kHeader)) {
                if (const uint32_t parent = g_docked_map.parent_of(*key); dgl::player_key(parent)) {
                    const uint32_t host_key = g_host_own_key.load(std::memory_order_relaxed);
                    const int c = host_key == 0 ? 2 : parent == host_key ? 1 : 0;
                    g_user2_listed[c][i].fetch_add(1, std::memory_order_relaxed);
                    if (g_user2_listed_lines.fetch_add(1, std::memory_order_relaxed) < kUser2ListedLines) {
                        push(kEvUser2Listed, *key | (uint64_t{dgl::kWithheldOps[i]} << 32), parent,
                             static_cast<uint64_t>(c));
                    }
                }
            }
        }
    }
    if (dgl::touch_op(op)) {
        const auto key = game::fast<uint32_t>(packet + dgl::kHeader);
        if (!key || !dgl::world_key(*key)) return;
        if (dgl::TouchEntry* e = g_touch.get(*key)) {
            e->last_ms[who].store(GetTickCount64(), std::memory_order_relaxed);
            g_touches.fetch_add(1, std::memory_order_relaxed);
        }
        return;
    }
    if (op == dgl::kOpSceneSpawnReq) {
        g_spawn_reqs[who].fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (op != dgl::kOpSceneUnspawnReq) return;
    g_unspawn_reqs[who].fetch_add(1, std::memory_order_relaxed);
    uint8_t buf[5 + 16 * 4] = {};
    const size_t n = std::min<size_t>(sizeof buf, size - dgl::kHeader);
    if (!game::fast_read(packet + dgl::kHeader, buf, n)) return;
    uint32_t keys[16] = {};
    uint32_t total = 0;
    const size_t k = dgl::unspawn_keys(std::span<const uint8_t>(buf, n), keys, std::size(keys), &total);
    if (total > k) g_unspawn_keys_not_measured.fetch_add(total - k, std::memory_order_relaxed);
    const uint64_t now = GetTickCount64();
    for (size_t i = 0; i < k; ++i) {
        const dgl::TouchEntry* e = g_touch.find(keys[i]);
        const uint64_t other = e ? e->last_ms[1 - who].load(std::memory_order_relaxed) : 0;
        const uint64_t self = e ? e->last_ms[who].load(std::memory_order_relaxed) : 0;
        g_unspawn[who][dgl::age_bucket(now, other)].fetch_add(1, std::memory_order_relaxed);
        if (g_unspawn_lines.fetch_add(1, std::memory_order_relaxed) < kUnspawnEventLines) {
            push(kEvUnspawn, keys[i] | (uint64_t(who) << 32),
                 other && other <= now ? now - other : static_cast<uint64_t>(-1),
                 self && self <= now ? now - self : static_cast<uint64_t>(-1));
        }
    }
}

// ---------------------------------------------------------------- start

namespace {
// Once per process, for docked_gimmicks and gimmick_event_dedup alike (mod.cpp's worker): the build check, the role
// and the module's thread. False: unsupported build (both stay off).
std::atomic<int> g_common{0};  // 0 not yet, 1 running, -1 refused
bool start_common(bool guest) {
    if (g_started.exchange(true)) return g_common.load() == 1;
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    if (!build_ok()) {
        g_common.store(-1);
        log::error("DockedGimmicks: unsupported game build (not 1.0.0.2976, 1.0.0.3527, 1.0.0.3576 or 1.0.0.3663); docked_gimmicks "
                   "and gimmick_event_dedup stay off");
        return false;
    }
    g_guest.store(guest);
    g_common.store(1);
    if (HANDLE h = CreateThread(nullptr, 0, worker_thread, nullptr, 0, nullptr)) CloseHandle(h);
    return true;
}
}  // namespace

void gimmick_event_dedup_start(const std::string& raw, bool guest) {
    const dgl::ParsedMode pm = dgl::parse_mode(raw);
    if (!pm.ok) log::warn("GimmickEventDedup: gimmick_event_dedup '{}' is not 0 | probe | 1; it stays off", raw);
    if (pm.mode == dgl::Mode::Off) return;
    // 3527: the 2779 / 2250 layouts this mode parses have not been checked (no 2779 in the captures); only docked_gimmicks
    // is ported. As before this module knew 3527, it stays off there.
    if (game::current_build() == game::Build::v3527 || game::current_build() == game::Build::v3576 ||
        game::current_build() == game::Build::v3663) {
        log::warn("GimmickEventDedup: not ported to 1.0.0.{} (2779 / 2250 unverified); gimmick_event_dedup stays off",
                  game::current_build() == game::Build::v3663   ? 3663
                  : game::current_build() == game::Build::v3576 ? 3576
                                                                : 3527);
        return;
    }
    // Set before the thread exists: the worker installs docked_gimmicks' hooks only when that mode is on.
    g_dedup_mode.store(static_cast<uint8_t>(pm.mode));
    if (!start_common(guest)) {
        g_dedup_mode.store(0);
        return;
    }
    if (!guest) {
        sniffer_tap_docked_gimmicks();  // the host client's 2250 (needs [sniffer] enabled=1)
        g_server_probe.store(true);     // the 2779 at the server's receive
    }
    log::info("GimmickEventDedup ON ({}, gimmick_event_dedup={}): {} (docs/research/s25/gimmicks-dueno.md section 7)",
              guest ? "guest" : "host", dgl::mode_name(pm.mode),
              guest ? (pm.mode == dgl::Mode::On
                           ? "an outgoing CreateProjectileFromGimmickEventReq 2779 whose gimmick the last 2005 says the "
                             "OTHER user controls is WITHHELD (the server has no controller check for it and creates "
                             "the projectile twice); unknown controller: sent"
                           : "every outgoing 2779 is decided and logged (would withhold / sent); nothing withheld")
                    : "log only: 2779 by origin at the server's receive, each 2250 of the host's client classified "
                      "(first / DUPLICATE created / index > 1 without both)");
}

void docked_gimmicks_other_start(const std::string& raw, bool guest) {
    const dgl::ParsedMode pm = dgl::parse_mode(raw);
    if (!pm.ok) log::warn("DockedGimmicks: docked_gimmicks_other '{}' is not 0 | probe | 1; it stays off", raw);
    if (pm.mode == dgl::Mode::Off) return;
    if (!guest) {
        log::info("DockedGimmicks: docked_gimmicks_other={} is a guest key: ignored on the host (its log-only side is "
                  "docked_gimmicks' 'TOTAL for the host's' and the client probe's 'docked to the other player's "
                  "character' class)",
                  dgl::mode_name(pm.mode));
        return;
    }
    if (mode() == dgl::Mode::Off) {
        log::warn("DockedGimmicks: docked_gimmicks_other={} needs docked_gimmicks probe or 1 (its delivery and send "
                  "points); it stays off",
                  dgl::mode_name(pm.mode));
        return;
    }
    g_other_mode.store(static_cast<uint8_t>(pm.mode));
    log::info("DockedGimmicks ON (guest, docked_gimmicks_other={}): {} (docs/research/s25/gimmicks-dueno.md section 8)",
              dgl::mode_name(pm.mode),
              pm.mode == dgl::Mode::On
                  ? "the host's 2005 'Game Mechanic' records docked to the OTHER player's character get this client's "
                    "user as controller (its client drives the host's device from the host character's replicated "
                    "actions: the host's rope drawn) and its state requests for them are withheld (the host stays the "
                    "controller and the only sender)"
                  : "the host's 2005 records docked to the other player's character are classified and counted "
                    "(would rewrite (other player) / would withhold); nothing changed");
}

void docked_gimmicks_start(const std::string& raw, bool guest) {
    const dgl::ParsedMode pm = dgl::parse_mode(raw);
    if (!pm.ok) log::warn("DockedGimmicks: docked_gimmicks '{}' is not 0 | probe | 1; it stays off", raw);
    if (pm.mode == dgl::Mode::Off) return;
    g_mode.store(static_cast<uint8_t>(pm.mode));
    if (!start_common(guest)) {
        g_mode.store(0);
        return;
    }
    if (!guest) {
        sniffer_tap_docked_gimmicks();  // the host's client 2005s (needs [sniffer] enabled=1)
        g_server_probe.store(true);     // the 2221 / keyed requests at the server's receive
    }
    log::info("DockedGimmicks ON ({}, docked_gimmicks={}): {}. Probe hooks (log only) once the world is up: the client's "
              "gimmick requests 0x8E59D0 / 0x8E5F60{}. Server authority (phase 2) is NOT in this build "
              "(docs/research/s25/gimmicks-dueno.md section 6)",
              guest ? "guest" : "host", dgl::mode_name(pm.mode),
              guest ? (pm.mode == dgl::Mode::On
                           ? "the host's 2005 records docked to THIS client's character get its user as controller "
                             "(local drive) and its state requests for them (3082 2758 2609 2774 3089 2779 2826 2618) are "
                             "withheld"
                           : "the host's 2005 records docked to this client's character are classified and counted "
                             "(would rewrite / would withhold); nothing changed")
                    : "the host's client is never changed (its own character's docked gimmicks are already its own; "
                      "user 2's are never taken); its 2005s are classified from the sniffer's capture (needs [sniffer] "
                      "enabled=1)",
              guest ? "" : "; server: the docking spawns 0x28AD170 / 0x28ADE40, the controller write 0x2792A7B, "
                           "0x2AC1270 / 0x2AC0790 accepted or rejected, the 2221 unspawns at the server's receive");
}

void docked_gimmicks_interact_start(const std::string& raw, const std::string& events, bool guest) {
    const auto m = gil::parse_mode(raw);
    if (!m) {
        log::warn("GimmickInteract: guest_gimmick_interact '{}' is not 0 | trace | 1; it stays off", raw);
        return;
    }
    if (*m == gil::Mode::Off) return;
    if (!guest) {
        log::info("GimmickInteract: guest_gimmick_interact is a guest key; ignored on the host");
        return;
    }
    if (mode() == dgl::Mode::Off) {
        log::warn("GimmickInteract: guest_gimmick_interact needs docked_gimmicks (its client hooks); it stays off");
        return;
    }
    const auto ev = gil::parse_events(events);
    if (!ev) {
        log::warn("GimmickInteract: guest_gimmick_interact_events '{}' is not a list of at most {} hex hashes; it "
                  "stays off",
                  events, gil::kMaxEvents);
        return;
    }
    g_gi_events = *ev;  // before the hooks (the worker installs them once the world is up)
    g_gi_mode.store(static_cast<uint8_t>(*m));
    log::info("GimmickInteract ON (guest_gimmick_interact={}, {} event(s) listed): the client's gimmick requests "
              "refused because the host controls the gimmick are traced{}",
              gil::mode_name(*m), ev->n,
              *m == gil::Mode::On ? "; the listed events pass the control compare (the server still decides)" : "");
}

}  // namespace cdmp::session2
