#include "mod/session2/remote_visible.h"

#include <windows.h>

#include <safetyhook.hpp>

#include <atomic>
#include <cstring>
#include <format>

#include "mod/game/build_profile.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/focus_follow.h"
#include "mod/session2/focus_follow_logic.h"
#include "mod/session2/remote_visible_logic.h"

namespace cdmp::session2 {
namespace {

// Status' flag setter: (status, bit, set, fade, ...). It is called from 91 places
// with many bits, so the hook leaves on the first comparison for all of them but
// this one. Its entry changes nothing yet, and its return value is "flags changed".
constexpr uintptr_t kSetter = 0x18CC450;
constexpr uintptr_t kSetterRet = 0x18CC735;
constexpr uint8_t kSetterHead[] = {0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x10, 0x48, 0x89, 0x68, 0x18, 0x48,
                                   0x89, 0x70, 0x20, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57};
// The single store of the flags this hook keeps clear, and the handler it calls.
constexpr uintptr_t kSetterStore = 0x18CC4F1;
constexpr uint8_t kSetterStoreBytes[] = {0x49, 0x89, 0x9E, 0xB8, 0x03, 0x00, 0x00};
constexpr uintptr_t kClanHide = 0x231E00F;
constexpr uint8_t kClanHideBytes[] = {0xBA, 0x00, 0x00, 0x10, 0x00};

// Build 1.0.0.3576 (static, 2026-11-06; not yet run): the setter moved whole by +0xC40 with the same bytes (entry
// 0x18CD090, its `ret` 0x18CD375, the flags store 0x18CD131); the clan's hide 0x231E00F -> 0x231ED5F (+0xD50, same
// bytes, inside 0x231DEE0 -> 0x231EC30, and its call there still goes to 0x18CD090). World slot 0x71C0100 and
// ClientChildOnlyInGameActor 0x59127C8 -> 0x5914D58 (RTTI): reader_profile() may be null on 3576. The world ->
// +0x30 -> +0x58 local-user chain is interact_gate's, unchanged on 3576.
struct Sites {
    uintptr_t setter, setter_ret, setter_store, clan_hide;
};
constexpr Sites kSites3527{kSetter, kSetterRet, kSetterStore, kClanHide};
constexpr Sites kSites3576{0x18CD090, 0x18CD375, 0x18CD131, 0x231ED5F};
constexpr uintptr_t kWorldSlot3576 = 0x71C0100, kVtClientActor3576 = 0x5914D58;
// Build 1.0.0.3663 (static, 2026-11-13; never run): the setter is 0x1932980 (3527 + 0x66530; kSetterHead at its entry,
// .pdata to 0x1932C98), with the flags store `mov [r14+0x3B8],rbx` at +0xA1 = 0x1932A21 (the only copy of those 7
// bytes in the code section) and its `ret` at +0x2E5 = 0x1932C65 (after `pop rdi`, as on 3527); the clan's hide
// 0x231E00F -> 0x238FBAF (+0x12F in 0x238FA80, as in 3527's 0x231DEE0; `mov r8b,1 ; mov edx,0x100000` then the call
// to 0x1932980 at 0x238FBB8). World slot 0x72451C0; ClientChildOnlyInGameActor 0x5914D58 -> 0x5990BF0 (RTTI). The
// world -> +0x30 -> +0x58 local user is read so at 0xAC86C5.
constexpr Sites kSites3663{0x1932980, 0x1932C65, 0x1932A21, 0x238FBAF};
constexpr uintptr_t kWorldSlot3663 = 0x72451C0, kVtClientActor3663 = 0x5990BF0;

constexpr uint32_t kStatusActor = 0x08, kActorKey = 0x60, kActorUser = 0xA0;
constexpr uint32_t kWorldManager = 0x30, kManagerUser = 0x58;

SafetyHookMid g_hook;
uintptr_t g_base = 0, g_world_slot = 0, g_ret = 0, g_vt_client_actor = 0;
const Sites* g_sites = &kSites3527;
thread_local bool t_own_call = false;  // focus_follow's own hide
std::atomic<uint64_t> g_refused{0};
std::atomic<uint32_t> g_last_key{0};

template <class T>
bool read_at(uintptr_t address, T& value) noexcept {
    return address && game::safe_read(address, &value, sizeof value);
}

void on_status_flag(safetyhook::Context& ctx) {
    if (ctx.rdx != rvis::kHiddenByClanBit || (ctx.r8 & 0xFF) == 0 || t_own_call) return;
    uintptr_t actor = 0, actor_user = 0, world = 0, manager = 0, local_user = 0, actor_vt = 0;
    uint32_t key = 0;
    if (!read_at(ctx.rcx + kStatusActor, actor) || !read_at(actor + kActorKey, key) ||
        !read_at(actor + kActorUser, actor_user) || !read_at(g_world_slot, world) ||
        !read_at(world + kWorldManager, manager) || !read_at(manager + kManagerUser, local_user)) {
        return;
    }
    // A client's copy goes by what the other player said; a server's actor (or one unreadable) by the old rule.
    const bool client_copy = read_at(actor, actor_vt) && actor_vt == g_vt_client_actor;
    const ffl::Focus said = ffl::unpack(focus_follow_remote());
    const bool refuse = client_copy ? rvis::refuse_client_hide(ctx.rdx, true, key, actor_user, local_user, said.focus, said.main)
                                    : rvis::refuse_hide(ctx.rdx, true, key, actor_user, local_user);
    if (!refuse) return;
    g_refused.fetch_add(1, std::memory_order_relaxed);
    g_last_key.store(key, std::memory_order_relaxed);
    ctx.rax = 0;  // the setter's own "nothing changed"
    ctx.rip = g_ret;
}

}  // namespace

bool remote_visible_install() {
    const bool b3576 = game::current_build() == game::Build::v3576;
    const bool b3663 = game::current_build() == game::Build::v3663;
    if (game::current_build() != game::Build::v3527 && !b3576 && !b3663) return true;
    const auto* profile = game::reader_profile();
    if (!profile && !b3576 && !b3663) return false;
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    g_sites = b3663 ? &kSites3663 : b3576 ? &kSites3576 : &kSites3527;
    g_world_slot = g_base + (b3663 ? kWorldSlot3663 : b3576 ? kWorldSlot3576 : profile->world_system);
    g_vt_client_actor = g_base + (b3663   ? kVtClientActor3663
                                  : b3576 ? kVtClientActor3576
                                          : profile->vt_controlled_actor);
    g_ret = g_base + g_sites->setter_ret;
    const auto matches = [](uintptr_t rva, const uint8_t* bytes, size_t n) {
        uint8_t actual[32]{};
        return n <= sizeof actual && game::safe_read(g_base + rva, actual, n) && std::memcmp(actual, bytes, n) == 0;
    };
    constexpr uint8_t kRet[] = {0xC3};
    if (!matches(g_sites->setter, kSetterHead, sizeof kSetterHead) ||
        !matches(g_sites->setter_ret, kRet, sizeof kRet) ||
        !matches(g_sites->setter_store, kSetterStoreBytes, sizeof kSetterStoreBytes) ||
        !matches(g_sites->clan_hide, kClanHideBytes, sizeof kClanHideBytes)) {
        log::error("RemoteVisible: the executable does not match; the other player will stay invisible");
        return false;
    }
    g_hook = safetyhook::create_mid(reinterpret_cast<void*>(g_base + g_sites->setter), on_status_flag);
    if (!g_hook) {
        log::error("RemoteVisible: cannot hook exe+0x{:X}; the other player will stay invisible", g_sites->setter);
        return false;
    }
    log::info("RemoteVisible ON: another user's main character is not hidden by the mercenary clan's login rule "
              "(Status bit 0x{:X} at exe+0x{:X})",
              rvis::kHiddenByClanBit, g_sites->setter);
    return true;
}

bool remote_visible_ready() noexcept { return static_cast<bool>(g_hook); }

namespace {
// Status' setter (status, bit, set, fade, to the pending word), as 0x231CF30 and 0x231DEE0 call it. Alone in its
// function: no objects to unwind around the guard.
bool call_setter(uintptr_t status, bool set, bool pending) noexcept {
    using Setter = uint64_t(__fastcall*)(uintptr_t, uint64_t, uint8_t, float, uint8_t);
    const auto setter = reinterpret_cast<Setter>(g_base + g_sites->setter);
    __try {
        setter(status, rvis::kHiddenByClanBit, set ? 1 : 0, 0.0f, pending ? 1 : 0);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
}  // namespace

bool remote_visible_set_hidden(uintptr_t status, bool hidden, bool in_pending, bool in_flags) noexcept {
    if (!g_hook) return false;
    t_own_call = true;
    bool ok = true;
    if (in_flags) ok = call_setter(status, hidden, false) && ok;
    if (in_pending) ok = call_setter(status, hidden, true) && ok;
    t_own_call = false;
    return ok;
}

std::string remote_visible_describe() {
    const uint64_t refused = g_refused.load(std::memory_order_relaxed);
    if (!refused) return "remote visible: no hide refused yet";
    return std::format("remote visible: {} hide(s) of another user's character refused (last 0x{:08X})", refused,
                       g_last_key.load(std::memory_order_relaxed));
}

}  // namespace cdmp::session2
