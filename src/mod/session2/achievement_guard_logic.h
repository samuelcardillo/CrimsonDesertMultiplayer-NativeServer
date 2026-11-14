#pragma once
// The rule of achievement_guard (achievement_guard.h), with no game access (tests: tests/optd_achievement_guard_tests.cpp).
//
// Builds 1.0.0.3527 and 1.0.0.3549 (real code, the same in both; capstone on the PE of 3549, 2026-11-05):
//   pa::PlatformAchievementManager_Steam, vtable 0x5B762D0 (RTTI). Its vf2 0x19827C0 is the only code that reaches
//   ISteamUserStats (interface STEAMUSERSTATS_INTERFACE_VERSION013, kept at manager+0x10): GetAchievement (+0x28), the
//   progress stat (+0x18), SetAchievement (+0x30) and StoreStats (+0x48). Its by-value arguments (rdx, r8) are destroyed
//   by the function itself, at 0x1982A1E, the way out that also returns 1 ("done").
//   0x19827F3  mov rcx,[rcx+0x10] ; mov rdx,[r8]: the frame is built, r13 = this, r15 = rdx, rsi = r8 (the key, whose
//              [[r8]] is the achievement's name): the first point where the way out at 0x1982A1E is valid.
//
// Why: on 2026-11-05 the guest's Steam account got every achievement the HOST had, the moment it joined. In the host's
// world the guest's client holds the host's quest progress, and the game unlocks on Steam what that progress says. So, on
// the guest, once it has played on a host, nothing reaches Steam's achievements until the game is restarted.

#include <cstddef>
#include <cstdint>

namespace cdmp::session2::agd {

inline constexpr uintptr_t kVtSteamManager = 0x5B762D0;
inline constexpr uintptr_t kUnlock = 0x19827C0, kPoint = 0x19827F3, kWayOut = 0x1982A1E;
inline constexpr uint32_t kPatch = 7;
inline constexpr uint8_t kPointBytes[kPatch] = {0x48, 0x8B, 0x49, 0x10, 0x49, 0x8B, 0x10};
inline constexpr uint8_t kUnlockBytes[] = {0x44, 0x89, 0x4C, 0x24, 0x20, 0x4C, 0x89, 0x44, 0x24, 0x18, 0x48, 0x89, 0x54, 0x24, 0x10,
                                           0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57};
// mov rcx,r15 ; call 0x3D7CC0 ; nop ; mov rcx,rsi ; call 0x3E5CE0 ; mov al,1 (read live on 3549: no nop after the second call)
inline constexpr uint8_t kWayOutBytes[] = {0x49, 0x8B, 0xCF, 0xE8, 0x9A, 0x52, 0xA5, 0xFE, 0x90, 0x48, 0x8B, 0xCE,
                                           0xE8, 0xB1, 0x32, 0xA6, 0xFE, 0xB0, 0x01};

// Build 1.0.0.3576 (static, 2026-11-06; not yet run): the vtable by RTTI (vtable_map_3549_3576.json); its vf2 0x1983400
// is 3527's moved by +0xC40 (.pdata 0x1983400..0x19836C1), with the same 27-byte head and the point's same 7 bytes at
// +0x33. The way out at +0x25E has the same instructions; only its two calls' rel32 differ (their targets moved by
// +0x2E0: 0x3D7FA0 and 0x3E5FC0).
inline constexpr uintptr_t kVtSteamManager3576 = 0x5B783F8;
inline constexpr uintptr_t kUnlock3576 = 0x1983400, kPoint3576 = 0x1983433, kWayOut3576 = 0x198365E;
inline constexpr uint8_t kWayOutBytes3576[] = {0x49, 0x8B, 0xCF, 0xE8, 0x3A, 0x49, 0xA5, 0xFE, 0x90, 0x48, 0x8B, 0xCE,
                                               0xE8, 0x51, 0x29, 0xA6, 0xFE, 0xB0, 0x01};
static_assert(kPoint3576 - kUnlock3576 == kPoint - kUnlock && kWayOut3576 - kUnlock3576 == kWayOut - kUnlock);
static_assert(sizeof kWayOutBytes3576 == sizeof kWayOutBytes);

// Build 1.0.0.3663 (static, 2026-11-13; never run): the vtable by RTTI (vtable_map_3576_3663.json); its vf2 0x19E9070
// (3576 +0x65C70, .pdata 0x19E9070..0x19E9331, the same 0x2C1 bytes) has the same 27-byte head and the point's same 7
// bytes at +0x33. The way out at +0x25E has the same instructions (masked match, the only one in the function); only
// its two calls' rel32 differ (targets 0x3DB480 and 0x3E6F50).
inline constexpr uintptr_t kVtSteamManager3663 = 0x5BF4138;
inline constexpr uintptr_t kUnlock3663 = 0x19E9070, kPoint3663 = 0x19E90A3, kWayOut3663 = 0x19E92CE;
inline constexpr uint8_t kWayOutBytes3663[] = {0x49, 0x8B, 0xCF, 0xE8, 0xAA, 0x21, 0x9F, 0xFE, 0x90, 0x48, 0x8B, 0xCE,
                                               0xE8, 0x71, 0xDC, 0x9F, 0xFE, 0xB0, 0x01};
static_assert(kPoint3663 - kUnlock3663 == kPoint - kUnlock && kWayOut3663 - kUnlock3663 == kWayOut - kUnlock);
static_assert(sizeof kWayOutBytes3663 == sizeof kWayOutBytes);

// Sticky: once this guest has played in a host's world, its game holds the host's progress until it is restarted.
class Gate {
public:
    // remote_now: the guest plays on a host right now.
    bool blocks(bool remote_now) noexcept {
        if (remote_now) blocked_ = true;
        return blocked_;
    }
    bool blocked() const noexcept { return blocked_; }

private:
    bool blocked_ = false;
};

// At kPoint: skip the unlock (its arguments are still freed and it returns 1). way_out: the build's kWayOut.
template <class Context>
bool skip_unlock(Context& ctx, uintptr_t base, bool block, uintptr_t way_out = kWayOut) noexcept {
    if (!block) return false;
    ctx.rip = base + way_out;
    return true;
}

}  // namespace cdmp::session2::agd
