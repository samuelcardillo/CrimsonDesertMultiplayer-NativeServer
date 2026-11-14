#include "mod/session2/clock_gate.h"

#include <windows.h>

#include <safetyhook.hpp>

#include <atomic>
#include <cstring>
#include <format>

#include "mod/game/build_profile.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/clock_push.h"
#include "mod/session2/server.h"

namespace cdmp::session2 {
namespace {

// Entries and one instruction of each body, from the copy analysed in
// docs/research/pendientes/reloj/capstone_*.txt (prologues alone repeat).
constexpr uintptr_t kTravel = 0x2BC0A30;
constexpr uint8_t kTravelHead[] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48, 0x89, 0x7C, 0x24,
                                   0x20, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24,
                                   0xC9, 0x48, 0x81, 0xEC, 0xC0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xF2, 0x48, 0x8B, 0xF9};
constexpr uintptr_t kTravelOwnerCmp = 0x2BC0A78;  // cmp [rdx+0x180], eax
constexpr uint8_t kTravelOwnerCmpBytes[] = {0x39, 0x82, 0x80, 0x01, 0x00, 0x00};
constexpr uintptr_t kTravelGetterCall = 0x2BC0CC7;  // call 0x20E55A0 (non-owner branch)
constexpr uint8_t kTravelGetterCallBytes[] = {0xE8, 0xD4, 0x48, 0x52, 0xFF};
constexpr uintptr_t kLoading = 0x219D7F0;
constexpr uint8_t kLoadingHead[] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48,
                                    0x89, 0x7C, 0x24, 0x20, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
                                    0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x60, 0x4D, 0x8B,
                                    0xE9, 0x49, 0x8B, 0xF0, 0x4C, 0x8B, 0xF2, 0x48, 0x8B, 0xD9};
constexpr uintptr_t kLoadingFlagCmp = 0x219D82B;  // cmp [rbp+0x50], r12b ; je 0x219D941
constexpr uint8_t kLoadingFlagCmpBytes[] = {0x44, 0x38, 0x65, 0x50, 0x0F, 0x84, 0x0C, 0x01, 0x00, 0x00};
constexpr uintptr_t kGetter = 0x20E55A0;
constexpr uint8_t kGetterHead[] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x60, 0x48, 0x8B, 0x01, 0x48,
                                   0x8B, 0xFA, 0x48, 0x8D, 0x54, 0x24, 0x70, 0x48, 0x8B, 0xD9, 0xFF, 0x50, 0x60};
constexpr uint64_t kMaxLogged = 24;

// 1.0.0.3527 kept LoadingComplete and GetCurrentFieldTime as native
// functions, but folded SyncFieldTimeOnMove into the larger MoveField path.
// Its owner branch still publishes the world clock; the non-owner branch at
// 0x2E620A1 only gets the destination field time and applies it to this TS.
// A mid hook on the comparison therefore preserves the whole native move and
// makes user 2 take that existing non-publishing branch.
constexpr uintptr_t kTravelOwnerCmp3527 = 0x2E61FB8;
constexpr uint8_t kTravelOwnerCmp3527Bytes[] = {0x39, 0x87, 0x80, 0x01, 0x00, 0x00};
constexpr uintptr_t kTravelGetterCall3527 = 0x2E620AC;
constexpr uint8_t kTravelGetterCall3527Bytes[] = {0xE8, 0xBF, 0x6E, 0x44, 0xFF};
constexpr uintptr_t kTravelSetterCall3527 = 0x2E620B7;
constexpr uint8_t kTravelSetterCall3527Bytes[] = {0xE8, 0xB4, 0xE4, 0x50, 0xFF};
constexpr uintptr_t kLoading3527 = 0x236B6B0;
constexpr uint8_t kLoadingHead3527[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x48,
                                        0x89, 0x7C, 0x24, 0x18, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
                                        0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x60, 0x4D, 0x8B,
                                        0xE9, 0x49, 0x8B, 0xF0, 0x4C, 0x8B, 0xF2, 0x48, 0x8B, 0xD9};
constexpr uintptr_t kLoadingFlagCmp3527 = 0x236B6EB;
constexpr uint8_t kLoadingFlagCmp3527Bytes[] = {0x44, 0x38, 0x65, 0x50, 0x0F, 0x84, 0x0C, 0x01, 0x00, 0x00};
constexpr uintptr_t kGetter3527 = 0x22A8F70;
constexpr uintptr_t kWorldTime3527 = 0x6EAB9B8;  // server-realm FieldTime
// Build 1.0.0.3576 (static, 2026-11-06; not yet run). MoveField moved whole by +0xC70: the owner check 0x2E61FB8 ->
// 0x2E62C28 (same bytes, still r15 = FieldMover, rdi = field, then jne to the non-owner branch 0x2E62D11), its getter
// call 0x2E620AC -> 0x2E62D1C and setter call 0x2E620B7 -> 0x2E62D27 (new rel32s). LoadingComplete 0x236B6B0 ->
// 0x236C400 and its flag check 0x236B6EB -> 0x236C43B (+0xD50, same bytes). GetCurrentFieldTime 0x22A8F70 -> 0x22A9BB0
// (+0xC40): the getter call's target, with kGetterHead. The world clock: the setter (thunk 0x23712C0 -> .tls$
// 0xCBCF310) stores the server-realm FieldTime at 0xCBCF380 into 0x6EAD9B8 (3527 0x6EAB9B8 + 0x2000, as the Troc
// block) when TLS +0x1EB is set and the owner matches; the client realm's is 0x6EAD998.
constexpr uintptr_t kTravelOwnerCmp3576 = 0x2E62C28;
constexpr uintptr_t kTravelGetterCall3576 = 0x2E62D1C;
constexpr uint8_t kTravelGetterCall3576Bytes[] = {0xE8, 0x8F, 0x6E, 0x44, 0xFF};  // 0x2E62D1C: call 0x22A9BB0
constexpr uintptr_t kTravelSetterCall3576 = 0x2E62D27;
constexpr uint8_t kTravelSetterCall3576Bytes[] = {0xE8, 0x94, 0xE5, 0x50, 0xFF};  // 0x2E62D27: call 0x23712C0
constexpr uintptr_t kLoading3576 = 0x236C400;
constexpr uintptr_t kLoadingFlagCmp3576 = 0x236C43B;
constexpr uintptr_t kGetter3576 = 0x22A9BB0;
constexpr uintptr_t kWorldTime3576 = 0x6EAD9B8;  // server-realm FieldTime
// Build 1.0.0.3663 (static, 2026-11-13; never run). MoveField is 0x2ECA480 (3527's 0x2E61990 + 0x68AF0; .pdata to
// 0x2ECB127; it calls AcquireField 0x2E08520 at 0x2ECAA51 and EnterField 0x2ECB130 at 0x2ECABD7, field_share.cpp). Its
// owner check moved register: `cmp [rsi+0x180],eax` at 0x2ECAABD (the destination field is now RSI; R15 is still the
// FieldMover, `mov r15,rcx` at 0x2ECA4A0, and eax is still [[[r15]+8]+0xA0]+0x60 or 0), then `jne 0x2ECABA4`, the
// non-owner branch: the getter call 0x2ECABAF (rcx = rsi, the field) to GetCurrentFieldTime 0x231A180 (kGetterHead
// unchanged) and the setter call 0x2ECABBA to the thunk 0x23E17C0 (jmp 0xD040130 in the protected section: stores the
// 32 bytes at TS+0x450, and when TLS +0x1EB is set and [field+0x180] == [[TS+8]+0xA0]+0x60 the server-realm FieldTime
// at 0x6F31C98; the client realm's is 0x6F31C78). The owner branch now publishes inline (0x2ECAB4C). LoadingComplete
// 0x236B6B0 -> 0x23DC630 (+0x70F80; the only one of the four `cmp [rbp+0x50],r12b ; je +0x10C` in the expected range,
// at +0x3B as on 3527); its head saves rbx/rsi/rdi at +0x10/+0x18/+0x20 (2976's head bytes, not 3527's), with 3527's
// argument moves (r13 = r9, rsi = r8, r14 = rdx, rbx = rcx); its flag path publishes 0x6F31C98 at 0x23DC72C.
constexpr uintptr_t kTravelOwnerCmp3663 = 0x2ECAABD;
constexpr uint8_t kTravelOwnerCmp3663Bytes[] = {0x39, 0x86, 0x80, 0x01, 0x00, 0x00};  // cmp [rsi+0x180],eax
constexpr uintptr_t kTravelGetterCall3663 = 0x2ECABAF;
constexpr uint8_t kTravelGetterCall3663Bytes[] = {0xE8, 0xCC, 0xF5, 0x44, 0xFF};  // 0x2ECABAF: call 0x231A180
constexpr uintptr_t kTravelSetterCall3663 = 0x2ECABBA;
constexpr uint8_t kTravelSetterCall3663Bytes[] = {0xE8, 0x01, 0x6C, 0x51, 0xFF};  // 0x2ECABBA: call 0x23E17C0
constexpr uintptr_t kLoading3663 = 0x23DC630;
constexpr uint8_t kLoadingHead3663[] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48,
                                        0x89, 0x7C, 0x24, 0x20, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
                                        0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x60, 0x4D, 0x8B,
                                        0xE9, 0x49, 0x8B, 0xF0, 0x4C, 0x8B, 0xF2, 0x48, 0x8B, 0xD9};
constexpr uintptr_t kLoadingFlagCmp3663 = 0x23DC66B;
constexpr uintptr_t kGetter3663 = 0x231A180;
constexpr uintptr_t kWorldTime3663 = 0x6F31C98;  // server-realm FieldTime

struct ClockProfile {
    game::Build build;
    uintptr_t loading;
    const uint8_t* loading_head;
    size_t loading_head_size;
    uintptr_t loading_flag_cmp;
    const uint8_t* loading_flag_bytes;
    size_t loading_flag_size;
    uintptr_t getter;
    uintptr_t world_time;
    bool travel_mid;
    // The mid hook's sites (travel_mid only): MoveField's owner check and its non-owner getter/setter calls.
    uintptr_t travel_cmp, getter_call, setter_call;
    const uint8_t* getter_call_bytes;
    const uint8_t* setter_call_bytes;
    // The owner check's bytes and the register that holds the destination field there (RDI on 3527/3576, RSI on 3663).
    const uint8_t* travel_cmp_bytes = kTravelOwnerCmp3527Bytes;
    bool field_in_rsi = false;
};

const ClockProfile* clock_profile() {
    static constexpr ClockProfile old{game::Build::v2976,
                                      kLoading,
                                      kLoadingHead,
                                      sizeof kLoadingHead,
                                      kLoadingFlagCmp,
                                      kLoadingFlagCmpBytes,
                                      sizeof kLoadingFlagCmpBytes,
                                      kGetter,
                                      clk::kWorldTime,
                                      false,
                                      0, 0, 0, nullptr, nullptr};
    static constexpr ClockProfile current{game::Build::v3527,
                                          kLoading3527,
                                          kLoadingHead3527,
                                          sizeof kLoadingHead3527,
                                          kLoadingFlagCmp3527,
                                          kLoadingFlagCmp3527Bytes,
                                          sizeof kLoadingFlagCmp3527Bytes,
                                          kGetter3527,
                                          kWorldTime3527,
                                          true,
                                          kTravelOwnerCmp3527, kTravelGetterCall3527, kTravelSetterCall3527,
                                          kTravelGetterCall3527Bytes, kTravelSetterCall3527Bytes};
    static constexpr ClockProfile current3576{game::Build::v3576,
                                              kLoading3576,
                                              kLoadingHead3527,
                                              sizeof kLoadingHead3527,
                                              kLoadingFlagCmp3576,
                                              kLoadingFlagCmp3527Bytes,
                                              sizeof kLoadingFlagCmp3527Bytes,
                                              kGetter3576,
                                              kWorldTime3576,
                                              true,
                                              kTravelOwnerCmp3576, kTravelGetterCall3576, kTravelSetterCall3576,
                                              kTravelGetterCall3576Bytes, kTravelSetterCall3576Bytes};
    static_assert(sizeof kTravelGetterCall3576Bytes == sizeof kTravelGetterCall3527Bytes &&
                  sizeof kTravelSetterCall3576Bytes == sizeof kTravelSetterCall3527Bytes);
    static constexpr ClockProfile current3663{game::Build::v3663,
                                              kLoading3663,
                                              kLoadingHead3663,
                                              sizeof kLoadingHead3663,
                                              kLoadingFlagCmp3663,
                                              kLoadingFlagCmp3527Bytes,
                                              sizeof kLoadingFlagCmp3527Bytes,
                                              kGetter3663,
                                              kWorldTime3663,
                                              true,
                                              kTravelOwnerCmp3663, kTravelGetterCall3663, kTravelSetterCall3663,
                                              kTravelGetterCall3663Bytes, kTravelSetterCall3663Bytes,
                                              kTravelOwnerCmp3663Bytes, true};
    static_assert(sizeof kTravelGetterCall3663Bytes == sizeof kTravelGetterCall3527Bytes &&
                  sizeof kTravelSetterCall3663Bytes == sizeof kTravelSetterCall3527Bytes &&
                  sizeof kTravelOwnerCmp3663Bytes == sizeof kTravelOwnerCmp3527Bytes);
    switch (game::current_build()) {
        case game::Build::v2976: return &old;
        case game::Build::v3527: return &current;
        case game::Build::v3576: return &current3576;
        case game::Build::v3663: return &current3663;
        default: return nullptr;
    }
}

ClockGame g_game{};
uintptr_t g_base = 0;
SafetyHookInline g_travel, g_loading;
SafetyHookMid g_travel_mid;
const ClockProfile* g_profile = nullptr;
std::atomic<bool> g_active{false};
std::atomic<uint64_t> g_travels{0}, g_travel_failed{0}, g_loadings{0}, g_flags_cut{0}, g_world_moved{0},
    g_logged{0}, g_world_changes{0}, g_world_frozen{0};
std::atomic<uint32_t> g_host_key{0};  // last host user key read (fallback when the lookup fails)
constexpr uint64_t kMaxWatchLogged = 60;

template <class T>
bool peek(uintptr_t a, T& v) {
    return a && game::safe_read(a, &v, sizeof v);
}

template <class... Args>
void note(std::format_string<Args...> fmt, Args&&... args) {
    if (g_logged.fetch_add(1) >= kMaxLogged) return;
    log::info(fmt, std::forward<Args>(args)...);
}

// The world clock, as the probe prints it (day, hour, minute, second, scale).
struct WorldTime {
    uint8_t raw[clk::kFieldTimeSize] = {};
    bool ok = false;
};

WorldTime world_now() {
    WorldTime w;
    w.ok = g_base && g_profile && game::safe_read(g_base + g_profile->world_time, w.raw, sizeof w.raw);
    return w;
}

std::string show(const uint8_t* ft) {
    uint32_t v[5] = {};
    uint16_t scale = 0;
    std::memcpy(v, ft, sizeof v);
    std::memcpy(&scale, ft + 0x16, sizeof scale);
    return std::format("day {} {:02}:{:02}:{:02} scale {}", v[0], v[1], v[2], v[3], scale);
}

std::string show(const WorldTime& w) { return w.ok ? show(w.raw) : std::string("unreadable"); }

// The global holds a base and its anchor: any change of its 32 bytes is a
// publish. Only two good reads count (no false "moved").
bool moved(const WorldTime& a, const WorldTime& b) {
    return a.ok && b.ok && std::memcmp(a.raw, b.raw, sizeof a.raw) != 0;
}

uint16_t scale_of(const WorldTime& w) {
    uint16_t s = 0;
    std::memcpy(&s, w.raw + 0x16, sizeof s);
    return s;
}

ClockWho who_now(uintptr_t ts) {
    uintptr_t host = 0, user2 = 0;
    uint32_t key = 0;
    if (server_host_user(host) && peek(host + clk::kUserKey, key) && key) {
        g_host_key.store(key);
    } else {
        key = g_host_key.load();
    }
    if (!server_user2(user2)) user2 = 0;
    return clock_who(ts, key, user2);
}

// Once a second: every publish of the world clock, by whoever.
DWORD WINAPI watch_thread(LPVOID) {
    WorldTime last = world_now();
    for (;;) {
        Sleep(1000);
        // P8 session 25 (clock_push.h, T2): the world clock to user 2 when it changed while user 2 is in the world.
        clock_push_tick(GetTickCount64());
        const WorldTime now = world_now();
        if (!moved(last, now)) {
            if (now.ok) last = now;
            continue;
        }
        g_world_changes.fetch_add(1);
        const bool frozen = scale_of(now) == 0;
        if (frozen) g_world_frozen.fetch_add(1);
        if (g_world_changes.load() <= kMaxWatchLogged || frozen) {
            log::info("Session2 clock watch: world clock published: {} -> {}{}", show(last), show(now),
                      frozen ? " | FROZEN (scale 0)" : "");
        }
        last = now;
    }
}

uintptr_t ts_of(void* fm) {
    uintptr_t ts = 0;
    return peek(reinterpret_cast<uintptr_t>(fm), ts) ? ts : 0;
}

// FieldMover::SyncFieldTimeOnMove(FM, destination field). Nothing may throw
// out of here; for user 2 the original never runs, not even on a failure.
void __fastcall travel_detour(void* fm, void* field) noexcept {
    bool gated = false;
    try {
        const uintptr_t ts = ts_of(fm);
        if (ts && who_now(ts) == ClockWho::User2) {
            gated = true;
            g_travels.fetch_add(1);
            const WorldTime before = world_now();
            const bool copied = clock_user2_travel(g_game, ts, reinterpret_cast<uintptr_t>(field));
            const WorldTime after = world_now();
            uint8_t mine[clk::kFieldTimeSize] = {};
            game::safe_read(ts + clk::kTsFieldTime, mine, sizeof mine);
            if (!copied) g_travel_failed.fetch_add(1);
            if (moved(before, after)) g_world_moved.fetch_add(1);
            uint32_t owner = 0;
            peek(reinterpret_cast<uintptr_t>(field) + 0x180, owner);
            note("Session2 clock gate: user 2 travels to field 0x{:X} (owner 0x{:X}): {} | world clock {} -> {}{}",
                 reinterpret_cast<uintptr_t>(field), owner,
                 copied ? "its character takes the field's time (" + show(mine) + "), nothing published"
                        : std::string("COPY FAILED, its character keeps its time; nothing published"),
                 show(before), show(after), moved(before, after) ? " (MOVED, by someone else)" : "");
        }
    } catch (...) {
    }
    if (!gated) g_travel.unsafe_call<void>(fm, field);
}

// 1.0.0.3527 (and 3576), immediately before `cmp dword ptr [rdi+0x180], eax`
// (3663: `cmp dword ptr [rsi+0x180], eax`, profile field_in_rsi).
// r15 is FieldMover and [r15] is its TransformSync.  For user 2, make eax
// unequal to the destination owner so the original JNE takes the game's
// existing getter+setter path.  No instruction is skipped or reimplemented.
void travel_owner_gate_3527(safetyhook::Context& ctx) noexcept {
    try {
        uintptr_t ts = 0;
        uint32_t owner = 0;
        const uintptr_t field = g_profile && g_profile->field_in_rsi ? ctx.rsi : ctx.rdi;
        if (!peek(ctx.r15, ts) || !ts || !peek(field + 0x180, owner) || who_now(ts) != ClockWho::User2) return;
        ctx.rax = (ctx.rax & 0xFFFFFFFF00000000ull) | static_cast<uint32_t>(owner ^ 0xFFFFFFFFu);
        g_travels.fetch_add(1);
        note("Session2 clock gate: user 2 move to field 0x{:X} (owner 0x{:X}) uses native non-owner time path; "
             "world clock is not published",
             field, owner);
    } catch (...) {
        // Leave the game's comparison untouched if identity or memory cannot
        // be inspected safely.
    }
}

// TransformSync LoadingComplete(TS, res, field, ?, u8 flag, now*) -> res.
uint32_t* __fastcall loading_detour(void* ts, uint32_t* res, void* field, void* r9, uint8_t flag,
                                    uint64_t* now) noexcept {
    uint8_t eff = flag;
    bool mine = false;
    WorldTime before;
    try {
        if (who_now(reinterpret_cast<uintptr_t>(ts)) == ClockWho::User2) {
            mine = true;
            eff = clock_loading_flag(ClockWho::User2, flag);
            g_loadings.fetch_add(1);
            if (eff != flag) g_flags_cut.fetch_add(1);
            before = world_now();
        }
    } catch (...) {
        if (mine) eff = 0;
    }
    uint32_t* r = g_loading.unsafe_call<uint32_t*>(ts, res, field, r9, eff, now);
    if (mine) {
        try {
            const WorldTime after = world_now();
            if (moved(before, after)) g_world_moved.fetch_add(1);
            uint32_t code = 0;
            peek(reinterpret_cast<uintptr_t>(r), code);
            note("Session2 clock gate: user 2's loading completes in field 0x{:X} (flag {} -> {}, result 0x{:X}) | "
                 "world clock {} -> {}{}",
                 reinterpret_cast<uintptr_t>(field), flag, eff, code, show(before), show(after),
                 moved(before, after) ? " (MOVED)" : "");
        } catch (...) {
        }
    }
    return r;
}

bool code_ok(uintptr_t rva, const uint8_t* bytes, size_t n, const char* what) {
    uint8_t actual[64] = {};
    if (n <= sizeof actual && game::safe_read(g_base + rva, actual, n) && std::memcmp(actual, bytes, n) == 0) {
        return true;
    }
    log::error("Session2 clock gate: {} (exe+0x{:X}) is not the expected code; the gate stays off", what, rva);
    return false;
}

}  // namespace

ClockWho clock_who(uintptr_t ts, uint32_t host_key, uintptr_t user2) {
    uintptr_t actor = 0, user = 0;
    if (!ts || !peek(ts + clk::kTsActor, actor) || !actor || !peek(actor + clk::kActorUser, user) || !user) {
        return ClockWho::Other;
    }
    if (user2 && user == user2) return ClockWho::User2;
    // Before the host is known (the game's own first load) nothing is gated:
    // no guest can be in yet, and the host's load must set the world clock.
    if (!host_key) return ClockWho::Other;
    uint32_t key = 0;
    if (peek(user + clk::kUserKey, key) && key == host_key) return ClockWho::Host;
    return ClockWho::User2;  // fail safe: a user that is not the host's
}

bool clock_user2_travel(const ClockGame& g, uintptr_t ts, uintptr_t field) {
    uintptr_t actor = 0;
    if (!ts || !field || !g.field_time || !peek(ts + clk::kTsActor, actor)) return false;
    alignas(32) uint8_t ft[clk::kFieldTimeSize] = {};
    void* got = g.field_time(reinterpret_cast<void*>(field), ft);
    if (!got) return false;
    // As the setter's own store (0xE52E910..0xE52E914), without what follows it.
    std::memcpy(reinterpret_cast<void*>(ts + clk::kTsFieldTime), got, clk::kFieldTimeSize);
    return true;
}

uint8_t clock_loading_flag(ClockWho who, uint8_t flag) { return who == ClockWho::User2 ? uint8_t{0} : flag; }

bool clock_gate_install() {
    if (g_active.load()) return true;
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    g_profile = clock_profile();
    if (!g_profile) {
        log::error("Session2 clock gate: unsupported executable; the gate stays off");
        return false;
    }
    const bool travel_code_ok = g_profile->travel_mid
        ? code_ok(g_profile->travel_cmp, g_profile->travel_cmp_bytes, sizeof kTravelOwnerCmp3527Bytes,
                  "MoveField owner-clock check") &&
              code_ok(g_profile->getter_call, g_profile->getter_call_bytes, sizeof kTravelGetterCall3527Bytes,
                      "its non-owner getter call") &&
              code_ok(g_profile->setter_call, g_profile->setter_call_bytes, sizeof kTravelSetterCall3527Bytes,
                      "its non-owner setter call")
        : code_ok(kTravel, kTravelHead, sizeof kTravelHead, "FieldMover::SyncFieldTimeOnMove") &&
              code_ok(kTravelOwnerCmp, kTravelOwnerCmpBytes, sizeof kTravelOwnerCmpBytes, "its owner check") &&
              code_ok(kTravelGetterCall, kTravelGetterCallBytes, sizeof kTravelGetterCallBytes, "its getter call");
    if (!travel_code_ok ||
        !code_ok(g_profile->loading, g_profile->loading_head, g_profile->loading_head_size,
                 "TransformSync LoadingComplete") ||
        !code_ok(g_profile->loading_flag_cmp, g_profile->loading_flag_bytes, g_profile->loading_flag_size,
                 "its flag check") ||
        !code_ok(g_profile->getter, kGetterHead, sizeof kGetterHead, "CommonField::GetCurrentFieldTime")) {
        return false;
    }
    g_game.field_time = reinterpret_cast<decltype(g_game.field_time)>(g_base + g_profile->getter);
    g_loading = safetyhook::create_inline(reinterpret_cast<void*>(g_base + g_profile->loading),
                                          reinterpret_cast<void*>(&loading_detour), SafetyHookInline::StartDisabled);
    if (!g_loading || !g_loading.enable()) {
        g_loading = {};
        log::error("Session2 clock gate: cannot hook LoadingComplete; the gate stays off");
        return false;
    }
    bool travel_hooked = false;
    if (g_profile->travel_mid) {
        g_travel_mid = safetyhook::create_mid(reinterpret_cast<void*>(g_base + g_profile->travel_cmp),
                                              &travel_owner_gate_3527);
        travel_hooked = static_cast<bool>(g_travel_mid);
    } else {
        g_travel = safetyhook::create_inline(reinterpret_cast<void*>(g_base + kTravel),
                                             reinterpret_cast<void*>(&travel_detour), SafetyHookInline::StartDisabled);
        travel_hooked = g_travel && g_travel.enable();
    }
    if (!travel_hooked) {
        (void)g_loading.disable();  // disabled, not destroyed: a thread may be inside
        log::error("Session2 clock gate: cannot hook the travel clock branch; the gate stays off");
        return false;
    }
    g_active.store(true);
    CloseHandle(CreateThread(nullptr, 0, watch_thread, nullptr, 0, nullptr));
    log::info("Session2 clock gate ON: user 2's travels and loads never publish the world clock "
              "(hooks exe+0x{:X} SyncFieldTimeOnMove, exe+0x{:X} LoadingComplete); world clock now {}",
              g_profile->travel_mid ? g_profile->travel_cmp : kTravel, g_profile->loading, show(world_now()));
    return true;
}

bool clock_gate_active() { return g_active.load(); }

std::string clock_gate_describe() {
    return std::format("clock gate: user 2 travels {} (copy failed {}), loads {} (flag cut {}), world clock moved "
                       "during them {} | world clock {}, publishes seen {} (frozen {}) | host key 0x{:X}",
                       g_travels.load(), g_travel_failed.load(), g_loadings.load(), g_flags_cut.load(),
                       g_world_moved.load(), show(world_now()), g_world_changes.load(), g_world_frozen.load(),
                       g_host_key.load());
}

}  // namespace cdmp::session2
