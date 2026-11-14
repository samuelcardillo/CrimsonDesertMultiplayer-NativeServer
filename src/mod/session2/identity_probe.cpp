#include "mod/session2/identity_probe.h"

#include <windows.h>

#include <intrin.h>

#include <safetyhook.hpp>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <format>

#include "mod/game/build_profile.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/offsets_s2.h"
#include "mod/session2/profile_s2.h"
#include "mod/session2/server.h"

#pragma intrinsic(_ReturnAddress)

namespace cdmp::session2 {
namespace {

// Expected code, decoded on instruction boundaries with capstone over the
// read-only copy of build 2976 (docs/research/pendientes/identidad-evidencias:
// capstone_20688a0.txt, capstone_20693c0.txt, capstone_2941020.txt,
// capstone_1791b77.txt, capstone_b742b0.txt; the others re-read for C2-0).
// No direct branch lands inside the bytes a hook overwrites (14 checked): no
// rel32 jmp/call/jcc in .rsrc/.xtls/.text/.xtext (raw byte scan), no short one
// in the containing function (linear disassembly). Jump tables not checked.
constexpr uintptr_t kLoad = 0x20688A0;  // LoadComponentsFromFile(actor, res*, store, name, u32 slot) -> res
constexpr uint8_t kLoadHead[] = {0x48, 0x89, 0x54, 0x24, 0x10, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x53, 0x56,
                                 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24,
                                 0x68, 0xFD, 0xFF, 0xFF, 0x48, 0x81, 0xEC, 0x98, 0x03, 0x00, 0x00, 0x49, 0x8B,
                                 0xD9, 0x4D, 0x8B, 0xE8, 0x48, 0x8B, 0xF2, 0x4C, 0x8B, 0xF1};
// mov rax,[r15] .. mov rcx,r15 ; call [rax+0x50] ; mov ebx,[rax] ; test ebx,ebx ; jne 0x2069482.
// The hook goes on the instruction after the call (0x20693EB): R15 (callee-saved)
// still holds the component, RAX the int* result.
constexpr uintptr_t kComponentSite = 0x20693CD;
constexpr uint8_t kComponentSiteBytes[] = {0x49, 0x8B, 0x07, 0x8B, 0x8D, 0x00, 0x03, 0x00, 0x00, 0x89,
                                           0x4C, 0x24, 0x20, 0x4C, 0x8D, 0x4D, 0xC0, 0x44, 0x8B, 0xC6,
                                           0x48, 0x8D, 0x55, 0x30, 0x49, 0x8B, 0xCF, 0xFF, 0x50, 0x50,
                                           0x8B, 0x18, 0x85, 0xDB, 0x0F, 0x85, 0x8D, 0x00, 0x00, 0x00};
constexpr uintptr_t kComponentHook = kComponentSite + 30;  // 0x20693EB
constexpr uintptr_t kOwner = 0x2AE1010;  // (component, u16* type, u64* no, u64* no2), void
constexpr uint8_t kOwnerHead[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74,
                                  0x24, 0x18, 0x48, 0x89, 0x7C, 0x24, 0x20, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x20,
                                  0x48, 0x8B, 0x59, 0x08, 0x49, 0x8B, 0xF9, 0x4D, 0x8B, 0xF0, 0x48, 0x8B, 0xF2,
                                  0x48, 0x8B, 0x43, 0x68, 0x48, 0x8B, 0xA8, 0x18, 0x01, 0x00, 0x00};
constexpr uintptr_t kPhases = 0x2941020;  // (obj, res*, ?, u32) -> res; actor = [obj+8] (0x2941049)
constexpr uint8_t kPhasesHead[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x44, 0x89, 0x4C, 0x24, 0x20, 0x4C, 0x89, 0x44,
                                   0x24, 0x18, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
                                   0x48, 0x8D, 0x6C, 0x24, 0xD9, 0x48, 0x81, 0xEC, 0xC0, 0x00, 0x00, 0x00, 0x4C,
                                   0x8B, 0xFA, 0x4C, 0x8B, 0x71, 0x08, 0x49, 0x8B, 0x7E, 0x78};
constexpr uintptr_t kAck = 0x28F31F0;  // (actor), void: the login path that writes CharacterStatAck 2358
constexpr uint8_t kAckHead[] = {0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55,
                                0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0xC8, 0x75, 0xFF, 0xFF, 0xB8,
                                0x38, 0x8B, 0x00, 0x00, 0xE8, 0xAD, 0x30, 0xFA, 0x01, 0x48, 0x2B, 0xE0, 0xC5,
                                0xF8, 0x29, 0xB4, 0x24, 0x20, 0x8B, 0x00, 0x00, 0x4C, 0x8B, 0xF1};
constexpr uintptr_t kPacker = 0x17908C0;  // (Status, archive), void: writes **(Status+0x70)
constexpr uint8_t kPackerHead[] = {0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
                                   0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x28, 0x4C, 0x8B,
                                   0xF9, 0x48, 0x8B, 0xDA, 0x48, 0x83, 0xC1, 0x30, 0xE8, 0x8D, 0x8C,
                                   0xBF, 0xFE, 0x41, 0xB8, 0x04, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xCB};
// CommonStatusActorComponent::LoadSaveData 0x1791980: mov rbp,rcx (0x17919A2) keeps
// the component in RBP; mov eax,[r11+0x60] ; mov [rip+..] = 0x6C8CD98, eax.
constexpr uintptr_t kVersionThis = 0x179199C;
constexpr uint8_t kVersionThisBytes[] = {0x49, 0x8B, 0xD9, 0x4C, 0x8B, 0xE2, 0x48, 0x8B, 0xE9, 0x48, 0x8B, 0x41, 0x08};
constexpr uintptr_t kVersionSite = 0x1791B94;
constexpr uint8_t kVersionSiteBytes[] = {0x41, 0x8B, 0x43, 0x60, 0x89, 0x05, 0xFA, 0xB1, 0x4F,
                                         0x05, 0x4C, 0x8B, 0x1D, 0xA3, 0x7E, 0x5D, 0x05};
constexpr uintptr_t kVersionHook = kVersionSite + 4;  // 0x1791B98
// CharacterStatAck handler 0xB73D70 (client): mov rcx,[rbx+0x70] ; mov [rcx],rax
// (0xB742B8, the characterNo) and, with RBX untouched, the global's write from R14D.
constexpr uintptr_t kClientStatus = 0xB742B0;
constexpr uint8_t kClientStatusBytes[] = {0x48, 0x8B, 0x4B, 0x70, 0x48, 0x8B, 0x45, 0xC0, 0x48, 0x89, 0x01};
constexpr uintptr_t kClientVersionSite = 0xB742F0;
constexpr uint8_t kClientVersionSiteBytes[] = {0x48, 0x8B, 0x4B, 0x18, 0xE8, 0xB7, 0x69, 0xC3, 0x00,
                                               0x48, 0x8B, 0x4B, 0x18, 0xE8, 0xCE, 0x75, 0xC3, 0x00,
                                               0x44, 0x89, 0x35, 0x8F, 0x8A, 0x11, 0x06};
constexpr uintptr_t kClientVersionHook = kClientVersionSite + 18;  // 0xB74302
constexpr uintptr_t kRestoreVersion = 0x6C8CD98;  // u32 _currentRestoreCodeVersionXXX (0x187C490)
constexpr uintptr_t kStatusVtable = 0x5B203F0;    // ServerStatusActorComponent (RTTI at its COL)
constexpr uintptr_t kStatusLoad = 0x293FE70;      // its +0x50: the 5-byte thunk to .xtls 0x10427500
constexpr uintptr_t kLoadStub = 0x35EA90;         // the shared vf50 stub (jmp .xtls 0x86F0570)

// Build 3527. The load entry is byte-for-byte identical apart from its RVA.
// The true Status login-phases function keeps the four-argument ABI and the
// actor = [obj+8] contract. (The earlier signature-only 0x2E13FB0 candidate
// belongs to ServerKnowledgeActorComponent and must never be hooked here.)
constexpr uintptr_t kLoad3527 = 0x2225250;
constexpr uintptr_t kPhases3527 = 0x2BB0D60;
constexpr uint8_t kPhases3527Head[] = {
    0x44, 0x89, 0x4C, 0x24, 0x20, 0x4C, 0x89, 0x44, 0x24, 0x18, 0x53, 0x55, 0x56,
    0x57, 0x41, 0x54, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0x80, 0x00, 0x00,
    0x00, 0x4C, 0x8B, 0xFA, 0x4C, 0x8B, 0x71, 0x08, 0x49, 0x8B, 0x7E, 0x78};
constexpr uintptr_t kStatusVtable3527 = 0x5EE7610;
constexpr uintptr_t kStatusLoad3527 = 0x2BAFA40;

// Build 1.0.0.3576 (static, 2026-11-06; not yet run). The load entry: kLoadHead (49 bytes) unique in the file at
// 3527's +0xC40 (.pdata 0x2225E90..0x2226CCE). The login phases: kPhases3527Head at 3527's +0xC70 (.pdata
// 0x2BB19D0..0x2BB1EA7). ServerStatusActorComponent's vtable by RTTI; its +0x50 is the 5-byte thunk at 3527's +0xC70,
// whose target 0xE390C80 is the same Status load as 3527's 0xE483B00: mov rax,[rdi+0x90] ; mov [rax],0x7FFF...FFFF,
// so Status -> u64* characterNo is +0x90 as in 3527 (identity_status_number_offset()).
constexpr uintptr_t kLoad3576 = 0x2225E90;
constexpr uintptr_t kPhases3576 = 0x2BB19D0;
constexpr uintptr_t kStatusVtable3576 = 0x5EE9828;
constexpr uintptr_t kStatusLoad3576 = 0x2BB06B0;
// Build 1.0.0.3663 (static, 2026-11-13; never run). The load entry: kLoadHead unique in the code section at 0x22951B0
// (3576 +0x6F320, .pdata 0x22951B0..0x2295FEE; it still reads the actor's descriptor at [r14+0x88] and the slot's
// +0x69C). The login phases: kPhases3527Head unique at 0x2C17410 (3576 +0x65A40, .pdata 0x2C17410..0x2C178E7).
// ServerStatusActorComponent's vtable 0x5F63430 by RTTI; its +0x50 is the 5-byte thunk 0x2C160B0 -> protected
// 0xE9F4150, the same Status load: mov rax,[rdi+0x90] (0xE9F419E) ; movabs rcx,0x7FFF...FFFF, so Status -> u64*
// characterNo is +0x90 as in 3527.
constexpr uintptr_t kLoad3663 = 0x22951B0;
constexpr uintptr_t kPhases3663 = 0x2C17410;
constexpr uintptr_t kStatusVtable3663 = 0x5F63430;
constexpr uintptr_t kStatusLoad3663 = 0x2C160B0;

struct IdentityProbeProfile {
    uintptr_t load, phases, status_vtable, status_load;
    const uint8_t* load_head;
    size_t load_head_size;
    const uint8_t* phases_head;
    size_t phases_head_size;
    bool legacy_probe_points;
};

const IdentityProbeProfile* identity_probe_profile() noexcept {
    static constexpr IdentityProbeProfile old{kLoad, kPhases, kStatusVtable, kStatusLoad,
                                               kLoadHead, sizeof kLoadHead, kPhasesHead, sizeof kPhasesHead, true};
    static constexpr IdentityProbeProfile current{kLoad3527, kPhases3527, kStatusVtable3527, kStatusLoad3527,
                                                   kLoadHead, sizeof kLoadHead, kPhases3527Head,
                                                   sizeof kPhases3527Head, false};
    static constexpr IdentityProbeProfile current3576{kLoad3576, kPhases3576, kStatusVtable3576, kStatusLoad3576,
                                                       kLoadHead, sizeof kLoadHead, kPhases3527Head,
                                                       sizeof kPhases3527Head, false};
    static constexpr IdentityProbeProfile current3663{kLoad3663, kPhases3663, kStatusVtable3663, kStatusLoad3663,
                                                       kLoadHead, sizeof kLoadHead, kPhases3527Head,
                                                       sizeof kPhases3527Head, false};
    switch (game::current_build()) {
        case game::Build::v2976: return &old;
        case game::Build::v3527: return &current;
        case game::Build::v3576: return &current3576;
        case game::Build::v3663: return &current3663;
        default: return nullptr;
    }
}

enum Point : int { kPtLoad, kPtComponent, kPtOwner, kPtPhases, kPtAck, kPtPacker, kPtVersion, kPtClientVersion, kPoints };
constexpr const char* kPointName[kPoints] = {"component load",        "component 0x20693EB",
                                             "owner 0x2AE1010",       "Status login phases",
                                             "2358 path 0x28F31F0",   "packer 0x17908C0",
                                             "version write 0x1791B98", "client version write 0xB74302"};
// Lines per point, the host's comparison lines per point and in total.
constexpr uint64_t kPointCap[kPoints] = {24, 80, 40, 8, 8, 16, 12, 8};
constexpr uint64_t kMaxHostLines = 2;
constexpr uint64_t kMaxLogged = 160;
// After user 2's first load (or its login phases / 2358), the packer and the
// owner builder are watched this long.
constexpr uint64_t kWindowMs = 60000;

struct PointStats {
    std::atomic<bool> on{false};
    std::atomic<uint64_t> calls{0}, user2{0}, tries{0}, host_tries{0}, lines{0};
};

uintptr_t g_base = 0, g_image_end = 0, g_status_vt = 0;
SafetyHookInline g_load, g_owner, g_phases, g_ack, g_packer;
SafetyHookMid g_component, g_version, g_client_version;
std::atomic<bool> g_active{false};  // the probe (its logging); the shared hooks may be on without it
// C2 fix (identity_fix.cpp), called from the shared entry hooks when set.
using AfterLoadFn = void (*)(uintptr_t, const int*) noexcept;
using BeforePhasesFn = void (*)(uintptr_t) noexcept;
std::atomic<AfterLoadFn> g_fix_after_load{nullptr};
std::atomic<BeforePhasesFn> g_fix_before_phases{nullptr};
// P8 session 25, the guest's own save (guest_save_host.cpp), called from the same entry hook when set.
using GuestBeforeFn = bool (*)(uintptr_t, int*, uintptr_t, uintptr_t, uint32_t) noexcept;
using GuestAfterFn = void (*)(uintptr_t, const int*, uint32_t) noexcept;
std::atomic<GuestBeforeFn> g_guest_before{nullptr};
std::atomic<GuestAfterFn> g_guest_after{nullptr};
PointStats g_pt[kPoints];
std::atomic<uint64_t> g_logged{0}, g_loads{0}, g_window_until{0};
std::atomic<uint32_t> g_host_key{0};  // last host user key read (fallback when the lookup fails)

// One per LoadComponentsFromFile running on this thread (it may nest).
struct LoadFrame {
    uintptr_t actor = 0;
    uint64_t id = 0;
    IdWho who = IdWho::Other;
    bool self = false;
    bool interesting = false;  // user 2's (or unidentified while session 2 exists): everything is logged
    bool host = false;         // the host's character: a couple of comparison lines
    bool entry_logged = false;
    bool no_ok = false;
    uint64_t no_at_entry = 0;
    uint32_t components = 0, stubs = 0, after_status = 0, owners = 0, status_index = 0;
};
constexpr int kMaxDepth = 4;
thread_local LoadFrame t_frames[kMaxDepth];
thread_local int t_depth = 0;

LoadFrame* current_frame() { return t_depth > 0 && t_depth <= kMaxDepth ? &t_frames[t_depth - 1] : nullptr; }

template <class T>
bool peek(uintptr_t a, T& v) {
    return a && game::safe_read(a, &v, sizeof v);
}

uintptr_t peekp(uintptr_t a) {
    uintptr_t v = 0;
    return peek(a, v) ? v : 0;
}

// Limited logging: per point, the host's lines per point, and in total.
// Callers are inside try blocks. True = the line was written.
template <class... Args>
bool note(Point p, bool host, std::format_string<Args...> fmt, Args&&... args) {
    PointStats& s = g_pt[p];
    if (host && s.host_tries.fetch_add(1) >= kMaxHostLines) return false;
    if (s.tries.fetch_add(1) >= kPointCap[p]) return false;
    if (g_logged.fetch_add(1) >= kMaxLogged) return false;
    s.lines.fetch_add(1);
    log::info("Session2 C2 probe: {}: {}{}", kPointName[p], host ? "[host, comparison] " : "",
              std::format(fmt, std::forward<Args>(args)...));
    return true;
}

std::string rva(uintptr_t a) {
    if (a >= g_base && a < g_image_end) return std::format("exe+0x{:X}", a - g_base);
    return std::format("0x{:X}", a);
}

std::string hex_or(bool ok, uint64_t v) { return ok ? std::format("0x{:X}", v) : std::string("unreadable"); }

std::string character_no(uintptr_t actor) {
    // Read first: the order in which a call's arguments are evaluated is
    // unspecified (MSVC copied `no` before the read and printed 0).
    uint64_t no = 0;
    const bool ok = identity_character_no(actor, no);
    return hex_or(ok, no);
}

// _currentRestoreCodeVersionXXX per build. 3527: the global the Status load 0xE483B00 compares with 4 at 0xE483B6F
// (tools/porting/data/identity_fields_3527.txt). 3576 (static, 2026-11-06; not yet run): the same compare in the same
// load 0xE390C80 (0xE390CEF), and the one global CommonStatusActorComponent::LoadSaveData 0x18C9190 writes at 0x18C93A4
// (the 2976 site's bytes, mov eax,[r11+0x60] ; mov [rip+..],eax). 0: unknown (logged as unreadable).
// Build 1.0.0.3663 (static, 2026-11-13; never run): 0x7160118, compared with 4 by the Status load 0xE9F4150 at
// 0xE9F41BF, and the global the only `mov eax,[r11+0x60] ; mov [rip+..],eax` site writes (0x192EC51, in
// CommonStatusActorComponent::LoadSaveData 0x192EA40); 21 code references.
uintptr_t restore_version_rva() {
    switch (game::current_build()) {
        case game::Build::v2976: return kRestoreVersion;
        case game::Build::v3527: return 0x70D9E90;
        case game::Build::v3576: return 0x70DBF98;
        case game::Build::v3663: return 0x7160118;
        default: return 0;
    }
}

std::string restore_version() {
    uint32_t v = 0;
    const uintptr_t at = restore_version_rva();
    const bool ok = at && peek(g_base + at, v);
    return hex_or(ok, v);
}

void open_window() { g_window_until.store(GetTickCount64() + kWindowMs); }
bool window_open() { return GetTickCount64() < g_window_until.load(std::memory_order_relaxed); }

IdUsers users_now() {
    IdUsers u;
    uint32_t key = 0;
    if (server_host_user(u.host) && peek(u.host + idp::kKey, key) && key) {
        g_host_key.store(key);
    } else {
        u.host = 0;
    }
    u.host_key = g_host_key.load();
    if (!server_user2(u.user2)) u.user2 = 0;
    return u;
}

struct Ident {
    IdWho who = IdWho::Other;
    bool self = false;
    uintptr_t owner = 0;
    uint32_t owner_key = 0, key = 0;
    bool user2() const { return who == IdWho::User2 || who == IdWho::User2ByKey; }
    bool host_character() const { return who == IdWho::Host && !self; }
};

Ident identify(uintptr_t actor) {
    Ident id;
    if (!actor) return id;
    // The build's ServerUserActor vtable (profile_s2.h; 0 = none: no actor is told to be a user actor).
    const uintptr_t user_vt_rva = profile::rva(off::kServerUserActorVtable);
    const uintptr_t user_vt = user_vt_rva ? g_base + user_vt_rva : 0;
    id.who = identity_who(actor, users_now(), user_vt, id.self);
    id.owner = identity_owner(actor, user_vt, id.self);
    peek(id.owner + idp::kKey, id.owner_key);
    peek(actor + idp::kKey, id.key);
    return id;
}

std::string who_text(const Ident& id) {
    switch (id.who) {
    case IdWho::User2:
        return id.self ? "user 2 (its user actor)" : "user 2's character";
    case IdWho::User2ByKey:
        return std::format("{} (BY KEY: its user 0x{:X} key 0x{:X} is not the host's; session 2's user not "
                           "readable yet)",
                           id.self ? "user 2?" : "user 2's character?", id.owner, id.owner_key);
    case IdWho::Host:
        return id.self ? "the host (its user actor)" : "the host's character";
    default:
        return std::format("unidentified (user 0x{:X} key 0x{:X})", id.owner, id.owner_key);
    }
}

std::string actor_text(uintptr_t actor, const Ident& id) {
    return std::format("actor 0x{:X} key 0x{:X} = {}", actor, id.key, who_text(id));
}

// Where a call happens relative to the load running on this thread.
std::string where(const LoadFrame* f) {
    if (!f) return "outside any load";
    return std::format("inside load #{} after component #{} ({})", f->id, f->components,
                       f->status_index ? std::format("Status was #{}", f->status_index) : std::string("before Status"));
}

// ---------------------------------------------------------------- entry hooks

// Nothing may throw out of a detour; each calls the original with the same
// registers (and the stack argument) and returns what it returned.
int* __fastcall load_detour(void* actor, int* res, void* store, void* name, uint64_t slot) noexcept {
    const int depth = t_depth++;
    LoadFrame* f = depth < kMaxDepth ? &t_frames[depth] : nullptr;
    if (f) *f = LoadFrame{};
    // Without the probe (only the C2 fix) nothing is identified or logged here.
    const bool probe = g_active.load(std::memory_order_relaxed);
    if (probe) try {
        g_pt[kPtLoad].calls.fetch_add(1);
        if (f) {
            f->actor = reinterpret_cast<uintptr_t>(actor);
            f->id = g_loads.fetch_add(1) + 1;
            const Ident id = identify(f->actor);
            f->who = id.who;
            f->self = id.self;
            // An actor with no identified user during user 2's login (its window
            // is open or its user exists) is logged as well: the character's
            // user link may not be set yet when its save is loaded.
            f->interesting =
                id.user2() || (id.who == IdWho::Other && (window_open() || server_user2_present()));
            f->host = !f->interesting && id.host_character();
            if (!id.self) f->no_ok = identity_character_no(f->actor, f->no_at_entry);
            if (f->interesting) {
                open_window();
                if (id.user2()) g_pt[kPtLoad].user2.fetch_add(1);
            }
            if (f->interesting || f->host) {
                f->entry_logged = note(kPtLoad, f->host, "enter, load #{} {} | slot {} | characterNo {} | restore version {}",
                                       f->id, actor_text(f->actor, id), static_cast<uint32_t>(slot),
                                       id.self ? std::string("n/a (user actor)") : hex_or(f->no_ok, f->no_at_entry),
                                       restore_version());
            }
        }
    } catch (...) {
    }
    // P8 session 25: the guest's own save may prepare the slot first, or refuse the load (then *res is its error
    // and the original does not run).
    int* r = res;
    const GuestBeforeFn guest_before = g_guest_before.load(std::memory_order_acquire);
    if (!guest_before ||
        !guest_before(reinterpret_cast<uintptr_t>(actor), res, reinterpret_cast<uintptr_t>(store),
                      reinterpret_cast<uintptr_t>(name), static_cast<uint32_t>(slot))) {
        r = g_load.unsafe_call<int*>(actor, res, store, name, slot);
        if (const GuestAfterFn guest_after = g_guest_after.load(std::memory_order_acquire)) {
            guest_after(reinterpret_cast<uintptr_t>(actor), r, static_cast<uint32_t>(slot));
        }
    }
    // C2: the fix first (noexcept), so the probe's line shows its result.
    if (const AfterLoadFn fix = g_fix_after_load.load(std::memory_order_acquire)) {
        fix(reinterpret_cast<uintptr_t>(actor), r);
    }
    if (probe && f && f->entry_logged) {
        try {
            uint32_t code = 0;
            const bool code_ok = peek(reinterpret_cast<uintptr_t>(r), code);
            uint64_t no = 0;
            const bool no_ok = !f->self && identity_character_no(f->actor, no);
            note(kPtLoad, f->host,
                 "return, load #{} actor 0x{:X} | result {} | characterNo at entry {} -> at return {} | components "
                 "called {} ({} stub), Status #{}, {} non-stub after it | owner 0x2AE1010 calls inside {} | "
                 "restore version {}",
                 f->id, f->actor, hex_or(code_ok, code), f->self ? std::string("n/a") : hex_or(f->no_ok, f->no_at_entry),
                 f->self ? std::string("n/a") : hex_or(no_ok, no), f->components, f->stubs, f->status_index,
                 f->after_status, f->owners, restore_version());
        } catch (...) {
        }
    }
    --t_depth;
    return r;
}

// 0x2AE1010(component, u16* type, u64* no, u64* no2): void (RAX passed through).
uintptr_t __fastcall owner_detour(void* comp, void* type, void* no, void* no2) noexcept {
    void* const caller = _ReturnAddress();
    const uintptr_t r = g_owner.unsafe_call<uintptr_t>(comp, type, no, no2);
    try {
        LoadFrame* f = current_frame();
        const bool in_load = f && (f->interesting || f->host);
        if (in_load || window_open()) {
            g_pt[kPtOwner].calls.fetch_add(1);
            if (f) ++f->owners;
            const uintptr_t actor = peekp(reinterpret_cast<uintptr_t>(comp) + idp::kComponentOwner);
            const Ident id = identify(actor);
            if (id.user2()) g_pt[kPtOwner].user2.fetch_add(1);
            // Inside user 2's load every call; outside it only user 2's actors
            // (and the host's, for comparison).
            const bool host = (f && f->host) || (!(f && f->interesting) && id.who == IdWho::Host);
            if ((f && f->interesting) || id.user2() || host) {
                uint16_t t = 0;
                uint64_t copied = 0;
                const bool t_ok = peek(reinterpret_cast<uintptr_t>(type), t);
                const bool c_ok = peek(reinterpret_cast<uintptr_t>(no), copied);
                note(kPtOwner, host, "{} | caller {} | {} | owner type {} copied {} | characterNo now {}", where(f),
                     rva(reinterpret_cast<uintptr_t>(caller)), actor_text(actor, id), hex_or(t_ok, t),
                     hex_or(c_ok, copied), character_no(actor));
            }
        }
    } catch (...) {
    }
    return r;
}

// 0x2941020 / 0x2BB0D60: the character is [obj+8]. Both builds use the same
// four-argument ABI.
int* __fastcall phases_detour(void* obj, int* res, void* r8, uint64_t r9) noexcept {
    bool logged = false, host = false;
    uintptr_t actor = 0;
    // C2: the fix's invariant check first (noexcept); the probe then logs.
    if (const BeforePhasesFn fix = g_fix_before_phases.load(std::memory_order_acquire)) {
        fix(reinterpret_cast<uintptr_t>(obj));
    }
    if (g_active.load(std::memory_order_relaxed)) try {
        g_pt[kPtPhases].calls.fetch_add(1);
        actor = peekp(reinterpret_cast<uintptr_t>(obj) + 8);
        const Ident id = identify(actor);
        host = id.host_character();
        if (id.user2()) {
            g_pt[kPtPhases].user2.fetch_add(1);
            open_window();
        }
        if (id.user2() || host || (id.who == IdWho::Other && window_open())) {
            logged = note(kPtPhases, host, "enter | {} | characterNo {} | restore version {}", actor_text(actor, id),
                          character_no(actor), restore_version());
        }
    } catch (...) {
    }
    int* r = g_phases.unsafe_call<int*>(obj, res, r8, r9);
    if (logged) {
        try {
            uint32_t code = 0;
            const bool code_ok = peek(reinterpret_cast<uintptr_t>(r), code);
            note(kPtPhases, host, "return | actor 0x{:X} | result {} | characterNo {}", actor, hex_or(code_ok, code),
                 character_no(actor));
        } catch (...) {
        }
    }
    return r;
}

// 0x28F31F0(actor): void. Logged before the 2358 is written.
uintptr_t __fastcall ack_detour(void* actor, void* rdx, void* r8, void* r9) noexcept {
    void* const caller = _ReturnAddress();
    try {
        g_pt[kPtAck].calls.fetch_add(1);
        const auto a = reinterpret_cast<uintptr_t>(actor);
        const Ident id = identify(a);
        if (id.user2()) {
            g_pt[kPtAck].user2.fetch_add(1);
            open_window();
        }
        if (id.user2() || id.host_character() || (id.who == IdWho::Other && window_open())) {
            note(kPtAck, id.host_character(),
                 "{} | characterNo it publishes {} | restore version (read for the 2358) {} | caller {}",
                 actor_text(a, id), character_no(a), restore_version(), rva(reinterpret_cast<uintptr_t>(caller)));
        }
    } catch (...) {
    }
    return g_ack.unsafe_call<uintptr_t>(actor, rdx, r8, r9);
}

// 0x17908C0(Status, archive): void. Only while the login window is open.
uintptr_t __fastcall packer_detour(void* status, void* archive, void* r8, void* r9) noexcept {
    if (window_open()) {
        void* const caller = _ReturnAddress();
        try {
            g_pt[kPtPacker].calls.fetch_add(1);
            const uintptr_t actor = identity_status_actor(reinterpret_cast<uintptr_t>(status));
            const Ident id = identify(actor);
            if (id.user2()) g_pt[kPtPacker].user2.fetch_add(1);
            if (id.user2() || id.host_character()) {
                note(kPtPacker, id.host_character(), "Status 0x{:X} of {} | characterNo packed {} | caller {}",
                     reinterpret_cast<uintptr_t>(status), actor_text(actor, id), character_no(actor),
                     rva(reinterpret_cast<uintptr_t>(caller)));
            }
        } catch (...) {
        }
    }
    return g_packer.unsafe_call<uintptr_t>(status, archive, r8, r9);
}

// ---------------------------------------------------------------- mid hooks (read only)

// 0x20693EB, after a component's vf(+0x50): R15 = component, RAX = int* result.
void on_component(safetyhook::Context& ctx) noexcept {
    try {
        LoadFrame* f = current_frame();
        if (!f) return;
        g_pt[kPtComponent].calls.fetch_add(1);
        const uint32_t index = ++f->components;
        const uintptr_t comp = ctx.r15;
        const uintptr_t vt = peekp(comp);
        const uintptr_t vf = vt ? peekp(vt + 0x50) : 0;
        const bool status = g_status_vt && vt == g_status_vt;
        const bool stub = vf && vf == g_base + kLoadStub;
        const bool after = f->status_index && !status;
        if (status) f->status_index = index;
        if (stub) {
            ++f->stubs;
            return;  // counted only: the shared stub loads nothing
        }
        if (after) ++f->after_status;
        // The host: only Status and the first component after it.
        const bool host = f->host && (status || (after && f->after_status == 1));
        if (!f->interesting && !host) return;
        if (f->interesting && (f->who == IdWho::User2 || f->who == IdWho::User2ByKey)) {
            g_pt[kPtComponent].user2.fetch_add(1);
        }
        uint32_t code = 0;
        const bool code_ok = peek(ctx.rax, code);
        note(kPtComponent, host, "load #{} component #{} 0x{:X} vtable {}{} | vf50 {} | result {} | characterNo now {}",
             f->id, index, comp, rva(vt), status ? " (Status)" : "", rva(vf), hex_or(code_ok, code),
             f->self ? std::string("n/a (user actor)") : character_no(f->actor));
    } catch (...) {
    }
}

// 0x1791B98, the Status load's write of the global: EAX = new, RBP = component.
void on_version(safetyhook::Context& ctx) noexcept {
    try {
        g_pt[kPtVersion].calls.fetch_add(1);
        uint32_t old = 0;
        const bool old_ok = peek(g_base + kRestoreVersion, old);
        const auto now = static_cast<uint32_t>(ctx.rax);
        const uintptr_t actor = identity_status_actor(ctx.rbp);
        const Ident id = identify(actor);
        LoadFrame* f = current_frame();
        if (id.user2()) g_pt[kPtVersion].user2.fetch_add(1);
        const bool mine = id.user2() || (f && f->interesting) || (id.who == IdWho::Other && window_open());
        const bool host = !mine && id.who == IdWho::Host;
        if (mine || host) {
            note(kPtVersion, host, "Status 0x{:X} of {} | global 0x6C8CD98 {} -> 0x{:X} | {}", ctx.rbp,
                 actor_text(actor, id), hex_or(old_ok, old), now, where(f));
        }
    } catch (...) {
    }
}

// 0xB74302, the host's client applying a CharacterStatAck: R14D = new, RBX = its Status.
void on_client_version(safetyhook::Context& ctx) noexcept {
    try {
        g_pt[kPtClientVersion].calls.fetch_add(1);
        uint32_t old = 0;
        const bool old_ok = peek(g_base + kRestoreVersion, old);
        uint64_t no = 0;
        const bool no_ok = peek(peekp(ctx.rbx + identity_status_number_offset()), no);
        note(kPtClientVersion, false,
             "the host's client applies a CharacterStatAck: global 0x6C8CD98 {} -> 0x{:X} | its Status 0x{:X}, "
             "characterNo now {}",
             hex_or(old_ok, old), static_cast<uint32_t>(ctx.r14), ctx.rbx, hex_or(no_ok, no));
    } catch (...) {
    }
}

// ---------------------------------------------------------------- install

bool code_ok(uintptr_t rva_, const uint8_t* bytes, size_t n, const char* what) {
    uint8_t actual[64] = {};
    if (n <= sizeof actual && game::safe_read(g_base + rva_, actual, n) && std::memcmp(actual, bytes, n) == 0) {
        return true;
    }
    log::warn("Session2 C2 probe: {} (exe+0x{:X}) is not the expected code; that point stays off", what, rva_);
    return false;
}

template <class Fn>
bool hook_entry(Point p, uintptr_t at, const uint8_t* head, size_t n, SafetyHookInline& h, Fn detour) {
    if (g_pt[p].on.load()) return true;  // a shared entry hook already in place (probe or fix)
    if (!code_ok(at, head, n, kPointName[p])) return false;
    h = safetyhook::create_inline(reinterpret_cast<void*>(g_base + at), reinterpret_cast<void*>(detour),
                                  SafetyHookInline::StartDisabled);
    if (!h || !h.enable()) {
        h = {};
        log::warn("Session2 C2 probe: cannot hook {}; that point stays off", kPointName[p]);
        return false;
    }
    g_pt[p].on.store(true);
    return true;
}

bool hook_mid(Point p, uintptr_t at, SafetyHookMid& h, safetyhook::MidHookFn fn) {
    h = safetyhook::create_mid(reinterpret_cast<void*>(g_base + at), fn);
    if (!h) {
        log::warn("Session2 C2 probe: cannot hook {}; that point stays off", kPointName[p]);
        return false;
    }
    g_pt[p].on.store(true);
    return true;
}

}  // namespace

uintptr_t identity_owner(uintptr_t actor, uintptr_t user_vtable, bool& self) {
    self = false;
    uintptr_t vt = 0, owner = 0;
    if (!actor || !peek(actor, vt)) return 0;
    if (user_vtable && vt == user_vtable) {
        self = true;
        return actor;
    }
    return peek(actor + idp::kActorUser, owner) ? owner : 0;
}

IdWho identity_who(uintptr_t actor, const IdUsers& users, uintptr_t user_vtable, bool& self) {
    const uintptr_t owner = identity_owner(actor, user_vtable, self);
    if (!owner) return IdWho::Other;
    if (users.user2 && owner == users.user2) return IdWho::User2;
    if (users.host && owner == users.host) return IdWho::Host;
    uintptr_t vt = 0;
    uint32_t key = 0;
    if (!users.host_key || !peek(owner, vt) || vt != user_vtable || !peek(owner + idp::kKey, key)) {
        return IdWho::Other;
    }
    if (key == users.host_key) return IdWho::Host;
    // Fallback only while session 2's user cannot be read: any other user.
    return users.user2 ? IdWho::Other : IdWho::User2ByKey;
}

uint32_t identity_status_number_offset() noexcept {
    const auto b = game::current_build();
    // 3663: +0x90 too (the Status load 0xE9F4150, above).
    return identity_status_number_offset_for_build(b == game::Build::v3527 || b == game::Build::v3576 ||
                                                   b == game::Build::v3663);
}

bool identity_character_no_at(uintptr_t actor, uint64_t& no, uint32_t status_number_offset) {
    if (status_number_offset != idp::kStatusCharacterNo &&
        status_number_offset != idp::kStatusCharacterNo3527) return false;
    uintptr_t table = 0, status = 0, p = 0;
    return actor && peek(actor + idp::kActorComponents, table) && table && peek(table + idp::kTableStatus, status) &&
           status && peek(status + status_number_offset, p) && p && peek(p, no);
}

bool identity_character_no(uintptr_t actor, uint64_t& no) {
    return identity_character_no_at(actor, no, identity_status_number_offset());
}

uintptr_t identity_status_actor(uintptr_t status) {
    uintptr_t actor = 0, table = 0, back = 0;
    return status && peek(status + idp::kComponentOwner, actor) && actor &&
                   peek(actor + idp::kActorComponents, table) && table && peek(table + idp::kTableStatus, back) &&
                   back == status
               ? actor
               : 0;
}

namespace {

void init_base() {
    if (g_base) return;
    const auto base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    g_image_end = base + nt->OptionalHeader.SizeOfImage;
    g_base = base;
    const auto* p = identity_probe_profile();
    if (!p) {
        log::warn("Session2 C2 probe: unsupported game build");
        return;
    }
    // Status is told by its vtable, whose +0x50 must be the load the report names.
    uintptr_t vf = 0;
    if (peek(g_base + p->status_vtable + 0x50, vf) && vf == g_base + p->status_load) {
        g_status_vt = g_base + p->status_vtable;
    } else {
        log::warn("Session2 C2 probe: ServerStatusActorComponent's vtable (exe+0x{:X}) is not the expected one; "
                  "Status is not marked among the components",
                  p->status_vtable);
    }
}

}  // namespace

bool identity_shared_hooks_install(const IdentityFixCalls& calls) {
    init_base();
    const auto* p = identity_probe_profile();
    if (!p) return false;
    // The calls before the hooks go live (or at once, if the probe has them).
    g_fix_after_load.store(calls.after_load, std::memory_order_release);
    g_fix_before_phases.store(calls.before_phases, std::memory_order_release);
    const bool load = hook_entry(kPtLoad, p->load, p->load_head, p->load_head_size, g_load, &load_detour);
    const bool phases =
        hook_entry(kPtPhases, p->phases, p->phases_head, p->phases_head_size, g_phases, &phases_detour);
    if (load && phases) return true;
    // A hook that did go in stays (calling the original only); the fix does not run from it.
    g_fix_after_load.store(nullptr, std::memory_order_release);
    g_fix_before_phases.store(nullptr, std::memory_order_release);
    return false;
}

bool identity_load_hook_share(const GuestSaveLoadCalls& calls) {
    init_base();
    const auto* p = identity_probe_profile();
    if (!p) return false;
    // The calls before the hook goes live (or at once, if the fix or the probe has it).
    g_guest_after.store(calls.after, std::memory_order_release);
    g_guest_before.store(calls.before, std::memory_order_release);
    if (hook_entry(kPtLoad, p->load, p->load_head, p->load_head_size, g_load, &load_detour)) return true;
    g_guest_before.store(nullptr, std::memory_order_release);
    g_guest_after.store(nullptr, std::memory_order_release);
    return false;
}

bool identity_probe_install() {
    if (g_active.load()) return true;
    init_base();
    const auto* profile = identity_probe_profile();
    if (!profile) return false;
    // Each point on its own. The component hook needs the load hook (its frame).
    if (hook_entry(kPtLoad, profile->load, profile->load_head, profile->load_head_size, g_load, &load_detour) &&
        profile->legacy_probe_points &&
        code_ok(kComponentSite, kComponentSiteBytes, sizeof kComponentSiteBytes, kPointName[kPtComponent])) {
        hook_mid(kPtComponent, kComponentHook, g_component, on_component);
    }
    hook_entry(kPtPhases, profile->phases, profile->phases_head, profile->phases_head_size, g_phases, &phases_detour);
    if (profile->legacy_probe_points) {
        hook_entry(kPtOwner, kOwner, kOwnerHead, sizeof kOwnerHead, g_owner, &owner_detour);
        hook_entry(kPtAck, kAck, kAckHead, sizeof kAckHead, g_ack, &ack_detour);
        hook_entry(kPtPacker, kPacker, kPackerHead, sizeof kPackerHead, g_packer, &packer_detour);
    }
    if (profile->legacy_probe_points &&
        code_ok(kVersionThis, kVersionThisBytes, sizeof kVersionThisBytes, kPointName[kPtVersion]) &&
        code_ok(kVersionSite, kVersionSiteBytes, sizeof kVersionSiteBytes, kPointName[kPtVersion])) {
        hook_mid(kPtVersion, kVersionHook, g_version, on_version);
    }
    if (profile->legacy_probe_points &&
        code_ok(kClientStatus, kClientStatusBytes, sizeof kClientStatusBytes, kPointName[kPtClientVersion]) &&
        code_ok(kClientVersionSite, kClientVersionSiteBytes, sizeof kClientVersionSiteBytes,
                kPointName[kPtClientVersion])) {
        hook_mid(kPtClientVersion, kClientVersionHook, g_client_version, on_client_version);
    }
    std::string on, off;
    for (int p = 0; p < kPoints; ++p) (g_pt[p].on.load() ? on : off) += std::format(" {},", kPointName[p]);
    if (on.empty()) {
        log::warn("Session2 C2 probe: no point could be installed; the probe stays off");
        return false;
    }
    g_active.store(true);
    log::info("Session2 C2 probe ON (read only, user 2's characterNo during its login): on{} off{} | "
              "restore version now {}",
              on, off.empty() ? std::string(" none") : off, restore_version());
    return true;
}

bool identity_probe_active() { return g_active.load(); }

std::string identity_probe_describe() {
    std::string s = "C2 probe:";
    for (int p = 0; p < kPoints; ++p) {
        const PointStats& t = g_pt[p];
        if (!t.on.load()) {
            s += std::format(" {} off |", kPointName[p]);
            continue;
        }
        s += std::format(" {} calls {} user 2 {} lines {} |", kPointName[p], t.calls.load(), t.user2.load(),
                         t.lines.load());
    }
    s += std::format(" lines {} of {} | login window {}", std::min(g_logged.load(), kMaxLogged), kMaxLogged,
                     window_open() ? "open" : "closed");
    return s;
}

}  // namespace cdmp::session2
