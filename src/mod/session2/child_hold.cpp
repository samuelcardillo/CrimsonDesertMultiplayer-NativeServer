#include "mod/session2/child_hold.h"

#include <windows.h>

#include <intrin.h>

#include <safetyhook.hpp>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <format>
#include <iterator>
#include <mutex>

#include "mod/game/build_profile.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/child_settle_logic.h"
#include "mod/session2/family_order_logic.h"
#include "mod/session2/guest_lifecycle.h"
#include "mod/session2/observer_hold_acks.h"
#include "mod/session2/offsets_s2.h"
#include "mod/session2/p8_probe_logic.h"
#include "mod/session2/publication_gate_logic.h"
#include "mod/session2/profile_s2.h"
#include "mod/session2/server.h"
#include "mod/session2/user2_stages.h"

namespace cdmp::session2 {

using game::read;
using game::read_ptr;

// ------------------------------------------------------------------ pure logic (unit-tested)

namespace {

// Every read below exists in two flavours: game::SafeReads (VirtualQuery +
// SEH) for D-53's paths, exactly as before, and game::FastReads (SEH only, no
// VirtualQuery) for observer_hold's hot paths on the server's logic thread.
template <class M>
OwnerWho owner_who_with(const M& m, uintptr_t owner, uintptr_t user2, uintptr_t host, uint32_t host_key,
                        uintptr_t user_vtable) {
    if (!owner) return OwnerWho::None;
    if (user2 && owner == user2) return OwnerWho::Guest;
    // The host's own children: only by the very pointer its session reads, so
    // that plan_split always finds the host's session as the owner's.
    if (host && owner == host) return OwnerWho::Host;
    // Before the host is known nothing else is held (no guest can be in yet).
    if (!host_key) return OwnerWho::None;
    const auto key = m.template rd<uint32_t>(owner + hold::kUserKey);
    if (!key) return OwnerWho::None;
    // The host's key on another (or a not yet known) pointer: left native, the
    // host must never miss its own child.
    if (*key == host_key) return OwnerWho::None;
    if (user_vtable) {
        const auto vt = m.template rd<uintptr_t>(owner);
        if (!vt || *vt != user_vtable) return OwnerWho::None;  // not a user at all: leave it native
    }
    return OwnerWho::Guest;  // fail safe: a user that is not the host's
}

template <class M>
std::optional<uint8_t> restore_byte_with(const M& m, uintptr_t actor) {
    if (!actor) return std::nullopt;
    const auto comps = m.ptr(actor + hold::kActorComponents);
    const auto cc = comps ? m.ptr(*comps + hold::kComponentsCc) : std::nullopt;
    const auto back = cc ? m.template rd<uintptr_t>(*cc + hold::kCcActor) : std::nullopt;
    if (!back || *back != actor) return std::nullopt;
    const auto state = m.ptr(*cc + hold::kCcRestore);
    return state ? m.template rd<uint8_t>(*state + hold::kRestoreByte) : std::nullopt;
}

// S35 publication_gate: the three CC states (pubg::read_cc): Unknown (could not read it) is never Absent (the slot
// reads 0). restore_byte_with's nullopt is both; this tells them apart with the same read policy.
template <class M>
pubg::CcRead cc_state_with(const M& m, uintptr_t actor) {
    const auto rd = [&m](uintptr_t a, void* out, size_t n) -> bool {
        if (n == sizeof(uintptr_t)) {
            const auto v = m.template rd<uintptr_t>(a);
            if (!v) return false;
            std::memcpy(out, &*v, n);
            return true;
        }
        if (n == 1) {
            const auto v = m.template rd<uint8_t>(a);
            if (!v) return false;
            std::memcpy(out, &*v, 1);
            return true;
        }
        return false;
    };
    pubg::CcOffsets o;
    o.components = hold::kActorComponents;
    o.cc = hold::kComponentsCc;
    o.cc_actor = hold::kCcActor;
    o.cc_restore = hold::kCcRestore;
    o.restore_byte = hold::kRestoreByte;
    return pubg::read_cc(rd, actor, o);
}

template <class M>
std::optional<uintptr_t> sector_with(const M& m, uintptr_t actor) {
    if (!actor) return std::nullopt;
    const auto comps = m.ptr(actor + hold::kActorComponents);
    const auto ts = comps ? m.ptr(*comps + hold::kComponentsTs) : std::nullopt;
    const auto back = ts ? m.template rd<uintptr_t>(*ts + hold::kTsActor) : std::nullopt;
    if (!back || *back != actor) return std::nullopt;
    // 3527's +0x548 on 3527/3549 and on 3576 (static, 2026-11-06: ToNearExceptOneControl 0x2D05490 and
    // ToNearExceptOneSelf 0x2D05360 read it with the same bytes, 3527's sites + 0xC70). 3663 (static, 2026-11-13):
    // the same +0x548 read at 0x2D6C3E0 / 0x2D6C2B0 (ToNearExceptOneControl / ToNearExceptOneSelf vf1).
    const game::Build build = game::current_build();
    const uint32_t sector_offset =
        build == game::Build::v3527 || build == game::Build::v3576 || build == game::Build::v3663
            ? hold::kTsSector3527 : hold::kTsSector;
    return m.template rd<uintptr_t>(*ts + sector_offset);
}

template <class M>
std::optional<bool> observed_by_with(const M& m, uintptr_t sector, uintptr_t user) {
    if (!sector) return false;  // in no sector: nobody observes it
    if (!user) return std::nullopt;
    const auto count = m.template rd<uint32_t>(sector + hold::kSectorObserverCount);
    if (!count || *count > hold::kMaxObservers) return std::nullopt;  // torn (the sector's lock is not ours)
    if (*count == 0) return false;
    const auto data = m.ptr(sector + hold::kSectorObservers);
    if (!data) return std::nullopt;
    for (uint32_t i = 0; i < *count; ++i) {
        const auto u = m.template rd<uintptr_t>(*data + static_cast<uintptr_t>(i) * hold::kObserverStride);
        if (!u) return std::nullopt;
        if (*u == user) return true;
    }
    return false;
}

template <class M>
std::optional<uintptr_t> find_actor_with(const M& m, uintptr_t sam, uint32_t key) {
    // 3527 SAM vf4 (0x2D10C10, vtable 0x5EECE88): 0x2D10CCD..0x2D10D64
    // confirms the helper's index mask, +98/+9C/+A8/+B0 map and holder +4/+8. 3576 (static): the same reads in vf4
    // 0x2D11880 (vtable 0x5EEF0A8), 0x2D1193D..0x2D11994. 3663 (static, 2026-11-13): vf4 0x2D787E0 (vtable 0x5F69100),
    // the same reads at 0x2D788A4..0x2D788F0.
    auto actor = sam_find_actor_with(m, sam, key);
    if (!actor) actor = sam_find_actor_with(m, sam, key);  // the map has no lock here: ask twice
    return actor;
}

// observer_hold_pieces: the parent key in the actor's hierarchy component (hold::kComponentsHierarchy), with the
// component's own actor checked. 0: no parent (no hierarchy component, no key, or not an 0xB key other than its
// own). nullopt: unlinked (unreadable, or the component's actor is another one).
template <class M>
std::optional<uint32_t> piece_parent_with(const M& m, uintptr_t actor) {
    if (!actor) return std::nullopt;
    const auto comps = m.ptr(actor + hold::kActorComponents);
    if (!comps) return std::nullopt;
    const auto slot = m.template rd<uintptr_t>(*comps + hold::kComponentsHierarchy);
    if (!slot) return std::nullopt;
    if (!*slot) return uint32_t{0};  // no hierarchy component: nothing to follow
    const auto hier = m.ptr(*comps + hold::kComponentsHierarchy);
    const auto back = hier ? m.template rd<uintptr_t>(*hier + hold::kHierActor) : std::nullopt;
    if (!back || *back != actor) return std::nullopt;
    const auto parent = m.template rd<uint32_t>(*hier + hold::kHierParent);
    if (!parent) return std::nullopt;
    const auto own = m.template rd<uint32_t>(actor + hold::kActorKey);
    if ((*parent >> 28) != hold::kChildKeyClass || (own && *own == *parent)) return uint32_t{0};
    return *parent;
}

// observer_hold's half of the predicate: an NPC (owner 0) by its controller.
template <class M>
void npc_verdict_with(const M& m, HoldVerdict& v, const ObserverHoldUsers& u) {
    const auto ctrl = m.template rd<uint32_t>(v.actor + hold::kActorController);
    if (!ctrl) {
        v.why = HoldWhy::Unreadable;
        return;
    }
    v.controller = *ctrl;
    uintptr_t user = 0;
    v.owner_who = npc_controller_who(*ctrl, u, user);
    if (v.owner_who == OwnerWho::None) {
        v.why = HoldWhy::CtrlNotUser;
        return;
    }
    v.owner = user;
    if (const auto info = m.ptr(v.actor + hold::kActorInfo)) {
        v.type = m.template rd<uint8_t>(*info + hold::kInfoType).value_or(0);
    }
    const auto restore = restore_byte_with(m, v.actor);
    if (!restore) {
        v.why = HoldWhy::NoCc;  // gimmicks and anything without a control component: native
        // S35 publication_gate: only a CC PROVEN absent is native; one that could not be read is held (on) like a
        // restore-0 NPC (its release is decided by the gate), or counted (probe).
        if (u.pub_gate && cc_state_with(m, v.actor).state == pubg::Cc::Unknown) {
            v.cc_unknown = true;
            if (u.pub_gate >= static_cast<uint8_t>(pubg::Mode::On)) {
                v.npc = true;
                v.hold = true;
                v.why = HoldWhy::Hold;
            }
        }
        return;
    }
    if (*restore != 0) {
        v.why = HoldWhy::Restored;
        // observer_load_defer: an NPC of the host that already acted, announced while user 2 loads (the field
        // snapshot of MoveFieldCompleteCore, session 13: 531 records before user 2's 2144). Held with the key at
        // 2 (on), only marked with 1 (probe). An NPC user 2 controls is never deferred (it is its own).
        if (u.load_defer && u.user2_loading && v.owner_who == OwnerWho::Host && *restore == 1) {
            v.defer = true;
            if (u.load_defer >= 2) {
                v.npc = true;
                v.hold = true;
                v.why = HoldWhy::Hold;
            }
        }
        return;
    }
    v.npc = true;
    v.hold = true;
    v.why = HoldWhy::Hold;
}

// character_hold's half: a user's main character (0xA...) with restore 0.
template <class M>
HoldVerdict character_verdict_with(const M& m, uintptr_t sam, uint32_t key, uintptr_t user2, uintptr_t host,
                                   uint32_t host_key, uintptr_t user_vtable) {
    HoldVerdict v;
    const auto actor = find_actor_with(m, sam, key);
    if (!actor) {
        v.why = HoldWhy::Unreadable;
        return v;
    }
    if (!*actor) {
        v.why = HoldWhy::NotFound;
        return v;
    }
    v.actor = *actor;
    const auto owner = m.template rd<uintptr_t>(v.actor + hold::kActorOwner);
    if (!owner) {
        v.why = HoldWhy::Unreadable;
        return v;
    }
    if (!*owner) {
        v.why = HoldWhy::NoOwner;  // a character of nobody (the server's): never held
        return v;
    }
    v.owner = *owner;
    v.owner_who = owner_who_with(m, v.owner, user2, host, host_key, user_vtable);
    if (v.owner_who == OwnerWho::None) {
        v.why = HoldWhy::NotUser;
        return v;
    }
    // Its user's main character, by the user's own pointer back (else: native).
    const auto main = m.template rd<uintptr_t>(v.owner + hold::kUserCharacter);
    if (!main) {
        v.why = HoldWhy::Unreadable;
        return v;
    }
    if (*main != v.actor) {
        v.why = HoldWhy::NotMain;
        return v;
    }
    if (const auto info = m.ptr(v.actor + hold::kActorInfo)) {
        v.type = m.template rd<uint8_t>(*info + hold::kInfoType).value_or(0);
    }
    const auto restore = restore_byte_with(m, v.actor);
    if (!restore) {
        v.why = HoldWhy::NoCc;
        return v;
    }
    if (*restore != 0) {
        v.why = HoldWhy::Restored;
        return v;
    }
    v.character = true;
    v.hold = true;
    v.why = HoldWhy::Hold;
    return v;
}

// child_settle's candidate: a user's child of type 4/5/6 (any restore byte) and its owner's main character.
template <class M>
SettleCandidate settle_with(const M& m, uintptr_t sam, uint32_t key, uintptr_t user2, uintptr_t host,
                            uint32_t host_key, uintptr_t user_vtable) {
    SettleCandidate c;
    if ((key >> 28) != hold::kChildKeyClass) return c;
    const auto actor = find_actor_with(m, sam, key);
    if (!actor || !*actor) return c;
    const auto owner = m.template rd<uintptr_t>(*actor + hold::kActorOwner);
    if (!owner || !*owner) return c;  // an NPC (or unreadable): never
    const OwnerWho who = owner_who_with(m, *owner, user2, host, host_key, user_vtable);
    if (who == OwnerWho::None) return c;
    const auto info = m.ptr(*actor + hold::kActorInfo);
    const auto type = info ? m.template rd<uint8_t>(*info + hold::kInfoType) : std::nullopt;
    if (!type || !cst::settle_type(*type)) return c;
    const auto main = m.template rd<uintptr_t>(*owner + hold::kUserCharacter);
    if (!main || !*main) return c;
    const auto main_key = m.template rd<uint32_t>(*main + hold::kActorKey);
    if (!main_key || (*main_key >> 28) != hold::kCharKeyClass) return c;
    // The main character's own owner is this very user (character_hold's test, read back).
    const auto back = m.template rd<uintptr_t>(*main + hold::kActorOwner);
    if (!back || *back != *owner) return c;
    c.ok = true;
    c.actor = *actor;
    c.owner = *owner;
    c.owner_who = who;
    c.type = *type;
    c.main_key = *main_key;
    c.main_actor = *main;
    return c;
}

// child_settle: does `user` observe the sector of the main character `main` now (nullopt: unreadable)?
template <class M>
std::optional<bool> main_in_range_with(const M& m, uintptr_t main, uintptr_t user) {
    if (!main || !user) return std::nullopt;
    const auto sector = sector_with(m, main);
    if (!sector) return std::nullopt;
    return observed_by_with(m, *sector, user);
}

template <class M>
HoldVerdict verdict_with(const M& m, uintptr_t sam, uint32_t key, uintptr_t user2, uintptr_t host, uint32_t host_key,
                         uintptr_t user_vtable, bool children, const ObserverHoldUsers* npc, bool characters = false) {
    HoldVerdict v;
    // Users (0x9...) are never held. Characters (0xA...) only with
    // character_hold (D-48 gives user 2's Kliff its first action in the
    // parking field; an old script or a reset byte does not).
    if (characters && (key >> 28) == hold::kCharKeyClass) {
        return character_verdict_with(m, sam, key, user2, host, host_key, user_vtable);
    }
    if ((key >> 28) != hold::kChildKeyClass) return v;
    const auto actor = find_actor_with(m, sam, key);
    if (!actor) {
        v.why = HoldWhy::Unreadable;
        return v;
    }
    if (!*actor) {
        v.why = HoldWhy::NotFound;
        return v;
    }
    v.actor = *actor;
    const auto owner = m.template rd<uintptr_t>(v.actor + hold::kActorOwner);
    if (!owner) {
        v.why = HoldWhy::Unreadable;
        return v;
    }
    if (!*owner) {
        v.why = HoldWhy::NoOwner;  // an NPC
        if (npc) npc_verdict_with(m, v, *npc);
        return v;
    }
    if (!children) {
        v.why = HoldWhy::ChildrenOff;
        return v;
    }
    v.owner = *owner;
    v.owner_who = owner_who_with(m, v.owner, user2, host, host_key, user_vtable);
    if (v.owner_who == OwnerWho::None) {
        v.why = HoldWhy::NotUser;
        return v;
    }
    if (const auto info = m.ptr(v.actor + hold::kActorInfo)) {
        v.type = m.template rd<uint8_t>(*info + hold::kInfoType).value_or(0);
    }
    const auto restore = restore_byte_with(m, v.actor);
    if (!restore) {
        v.why = HoldWhy::NoCc;  // no control component (or unreadable): leave it native
        return v;
    }
    if (*restore != 0) {
        v.why = HoldWhy::Restored;
        return v;
    }
    v.hold = true;
    v.why = HoldWhy::Hold;
    return v;
}

}  // namespace

SettleCandidate settle_candidate(uintptr_t sam, uint32_t key, uintptr_t user2, uintptr_t host, uint32_t host_key,
                                 uintptr_t user_vtable) {
    return settle_with(game::FastReads{}, sam, key, user2, host, host_key, user_vtable);
}

OwnerWho hold_owner_who(uintptr_t owner, uintptr_t user2, uintptr_t host, uint32_t host_key, uintptr_t user_vtable) {
    return owner_who_with(game::SafeReads{}, owner, user2, host, host_key, user_vtable);
}

const char* owner_who_name(OwnerWho who) {
    switch (who) {
        case OwnerWho::None: return "nobody";
        case OwnerWho::Host: return "host";
        case OwnerWho::Guest: return "user 2";
    }
    return "?";
}

std::optional<uint8_t> child_restore_byte(uintptr_t actor) { return restore_byte_with(game::SafeReads{}, actor); }

std::optional<uintptr_t> child_sector(uintptr_t actor) { return sector_with(game::SafeReads{}, actor); }

std::optional<bool> sector_observed_by(uintptr_t sector, uintptr_t user) {
    return observed_by_with(game::SafeReads{}, sector, user);
}

const char* hold_why_name(HoldWhy why) {
    switch (why) {
        case HoldWhy::NotChildKey: return "not a child key";
        case HoldWhy::Unreadable: return "unreadable";
        case HoldWhy::NotFound: return "not in the SAM";
        case HoldWhy::NoOwner: return "no owner";
        case HoldWhy::NotUser: return "owner not a validated user";
        case HoldWhy::NoCc: return "no CC";
        case HoldWhy::Restored: return "restored";
        case HoldWhy::Hold: return "hold";
        case HoldWhy::ChildrenOff: return "a user's child (child_hold off)";
        case HoldWhy::CtrlNotUser: return "NPC not controlled by a known user";
        case HoldWhy::TableFull: return "table full";
        case HoldWhy::NotMain: return "not its user's main character";
    }
    return "?";
}

OwnerWho npc_controller_who(uint32_t controller, const ObserverHoldUsers& u, uintptr_t& user) {
    user = 0;
    if (!controller) return OwnerWho::None;  // the server's own NPC
    if (u.host && u.host_key && controller == u.host_key) {
        user = u.host;
        return OwnerWho::Host;
    }
    if (u.user2 && u.user2_key && controller == u.user2_key) {
        user = u.user2;
        return OwnerWho::Guest;
    }
    return OwnerWho::None;
}

// D-53 alone: the reads it always used.
HoldVerdict hold_verdict(uintptr_t sam, uint32_t key, uintptr_t user2, uintptr_t host, uint32_t host_key,
                         uintptr_t user_vtable) {
    return verdict_with(game::SafeReads{}, sam, key, user2, host, host_key, user_vtable, true, nullptr);
}

// observer_hold on: one NotifyAppear can carry hundreds of keys, SEH reads only.
HoldVerdict hold_verdict_ex(uintptr_t sam, uint32_t key, uintptr_t user2, uintptr_t host, uint32_t host_key,
                            uintptr_t user_vtable, bool children, const ObserverHoldUsers* npc) {
    return verdict_with(game::FastReads{}, sam, key, user2, host, host_key, user_vtable, children, npc);
}

HoldVerdict hold_verdict_rules(uintptr_t sam, uint32_t key, uintptr_t user2, uintptr_t host, uint32_t host_key,
                               uintptr_t user_vtable, const HoldRules& rules) {
    if (rules.fast) {
        return verdict_with(game::FastReads{}, sam, key, user2, host, host_key, user_vtable, rules.children, rules.npc,
                            rules.characters);
    }
    return verdict_with(game::SafeReads{}, sam, key, user2, host, host_key, user_vtable, rules.children, rules.npc,
                        rules.characters);
}

bool plan_split(std::span<const uintptr_t> sessions, std::span<const uintptr_t> users, uintptr_t host,
                std::span<const uint32_t> keys, std::span<const HoldVerdict> verdicts, SplitPlan& plan) {
    plan = SplitPlan{};
    if (sessions.size() != users.size() || keys.size() != verdicts.size()) return false;
    bool withheld = false;
    for (size_t j = 0; j < keys.size(); ++j) {
        const HoldVerdict& v = verdicts[j];
        bool someone_else = false;
        // A held verdict always has an owner (hold_verdict); without one it passes.
        if (v.hold && v.owner) {
            for (size_t i = 0; i < sessions.size(); ++i) {
                if (sessions[i] && users[i] != v.owner) someone_else = true;
            }
        }
        if (!someone_else) {
            plan.pass.push_back(keys[j]);
            continue;
        }
        withheld = true;
        auto g = std::find_if(plan.groups.begin(), plan.groups.end(),
                              [&](const HoldGroup& x) { return x.owner == v.owner; });
        if (g == plan.groups.end()) {
            HoldGroup ng;
            ng.owner = v.owner;
            for (size_t i = 0; i < sessions.size(); ++i) {
                if (sessions[i] && users[i] == v.owner &&
                    std::find(ng.sessions.begin(), ng.sessions.end(), sessions[i]) == ng.sessions.end()) {
                    ng.sessions.push_back(sessions[i]);
                }
            }
            plan.groups.push_back(std::move(ng));
            g = plan.groups.end() - 1;
        }
        g->keys.push_back(keys[j]);
        for (size_t i = 0; i < sessions.size(); ++i) {
            if (!sessions[i] || users[i] == v.owner) continue;
            const bool dup = std::any_of(plan.records.begin(), plan.records.end(), [&](const HoldRecord& r) {
                return r.key == keys[j] && r.observer == sessions[i];
            });
            if (!dup) {
                plan.records.push_back({keys[j], sessions[i], users[i], v.owner, v.owner_who,
                                        host != 0 && users[i] == host, v.type, v.npc, v.controller, v.actor,
                                        v.character, v.settle, v.main_key, v.restore, v.main_in_call,
                                        v.defer && (v.npc || v.family), v.family, v.parent, v.family_why});
                plan.records.back().no_entry = v.no_entry;
            }
        }
    }
    if (!withheld) plan = SplitPlan{};
    return withheld;
}

std::optional<uint32_t> piece_parent_key(uintptr_t actor) {
    return piece_parent_with(game::FastReads{}, actor);
}

const char* family_why_name(FamilyWhy w) {
    switch (w) {
        case FamilyWhy::ParentInCall: return "its parent is withheld there in this same NotifyAppear";
        case FamilyWhy::ParentHeld: return "its parent is withheld there";
        case FamilyWhy::ParentUnknown: return "its parent has not been announced to user 2 yet";
        case FamilyWhy::ReleaseBlocked: return "its own release was due before its parent reached user 2";
    }
    return "?";
}

const char* family_release_name(FamilyRelease k) {
    switch (k) {
        case FamilyRelease::None: return "-";
        case FamilyRelease::WithParent: return "behind its parent, in its release";
        case FamilyRelease::AfterParent: return "right after its parent reached that session";
        case FamilyRelease::Orphan: return "its parent's entry went without it: announced natively";
        case FamilyRelease::OrphanTimeout: return "ITS PARENT NEVER CAME: announced natively (an orphan)";
        case FamilyRelease::MaxAge: return "STILL WITHHELD with its parent after the max wait: announced natively";
    }
    return "?";
}

ReleaseStep family_release_step(const HoldEntry& e, const FamilyReadings& r, uint64_t age_ms, uint64_t wait_ms,
                                const char*& why, FamilyRelease* kind) {
    auto out = [&](ReleaseStep s, const char* w, FamilyRelease k) {
        why = w;
        if (kind) *kind = k;
        return s;
    };
    if (r.epoch_now != e.epoch) return out(ReleaseStep::Drop, "another guest epoch", FamilyRelease::None);
    const bool too_old = age_ms >= hold::kFamilyMaxHoldMs;
    if (!r.actor) {
        return too_old ? out(ReleaseStep::Drop, "stale (member unreadable for too long)", FamilyRelease::None)
                       : out(ReleaseStep::Keep, "member unreadable", FamilyRelease::None);
    }
    if (!*r.actor) return out(ReleaseStep::Drop, "despawned", FamilyRelease::None);
    if (!r.observer_valid || r.observer_user != e.observer_user) {
        return out(ReleaseStep::Drop, "observer gone", FamilyRelease::None);
    }
    if (r.parent_held && !too_old) return out(ReleaseStep::Keep, "its parent is still withheld", FamilyRelease::None);
    // Out of the observer's range now: the engine announces it again when it comes back.
    if (r.observes && !*r.observes) return out(ReleaseStep::Drop, "observer out of range", FamilyRelease::None);
    if (r.parent_held) return out(ReleaseStep::Release, "still withheld after the max wait", FamilyRelease::MaxAge);
    // The host's session: nothing tracks what it has; its parent is not withheld any more (as observer_hold_pieces).
    if (!r.tracks) {
        return out(ReleaseStep::Release, "orphan (its parent's entry went without it)", FamilyRelease::Orphan);
    }
    if (r.parent_known) return out(ReleaseStep::Release, "its parent reached user 2", FamilyRelease::AfterParent);
    if (wait_ms < hold::kFamilyOrphanMs) {
        return out(ReleaseStep::Keep, "waiting for its parent's announcement", FamilyRelease::None);
    }
    return out(ReleaseStep::Release, "its parent never reached user 2", FamilyRelease::OrphanTimeout);
}

bool hold_drop_user2(bool user2_present, bool logout_handed) { return !user2_present || logout_handed; }

bool hold_entry_of_user2(const HoldEntry& e) { return e.owner_who != OwnerWho::Host || !e.observer_host; }

bool npc_entry_of_leaving_user2(const HoldEntry& e) { return !e.observer_host; }

NpcReleaseReadings read_npc_release(uintptr_t sam, uint32_t key, uintptr_t observer_user) {
    const game::FastReads m;
    NpcReleaseReadings r;
    r.actor = find_actor_with(m, sam, key);
    if (!r.actor || !*r.actor) return r;
    const uintptr_t actor = *r.actor;
    r.owner = m.rd<uintptr_t>(actor + hold::kActorOwner);
    r.controller = m.rd<uint32_t>(actor + hold::kActorController);
    r.restore = restore_byte_with(m, actor);
    if (const auto sector = sector_with(m, actor)) r.observes = observed_by_with(m, *sector, observer_user);
    return r;
}

const char* npc_release_name(NpcRelease k) {
    switch (k) {
        case NpcRelease::None: return "-";
        case NpcRelease::Restore1: return "restore 1";
        case NpcRelease::ByControl: return "the observer is now its controller";
        case NpcRelease::Timeout: return "TIMEOUT, still restore 0";
        case NpcRelease::Native: return "announced natively instead of dropped";
        case NpcRelease::WithheldUser2: return "withheld from the host: user 2 controls it, restore 0";
    }
    return "?";
}

ReleaseStep npc_release_step(const HoldEntry& e, const NpcReleaseReadings& r, uint64_t age_ms, const char*& why,
                             NpcRelease* kind, bool children_rule) {
    auto out = [&](ReleaseStep s, const char* w, NpcRelease k) {
        why = w;
        if (kind) *kind = k;
        return s;
    };
    if (r.epoch_now != e.epoch) return out(ReleaseStep::Drop, "another guest epoch", NpcRelease::None);
    const bool stale = age_ms >= 3 * hold::kNpcTimeoutMs;
    // observer_load_defer: user 2 is still loading (no 2762 written for it yet): nothing is announced to it
    // before its 2762, at most hold::kLoadDeferMaxMs after the hold. Only the drops that cannot leave an NPC
    // invisible happen meanwhile (another epoch, despawned, observer gone); a reading that would drop it
    // otherwise (unreadable for too long, out of range: the observers of a sector may still be settling in
    // the load) is decided after the 2762 by the rules below.
    const bool load_hold = r.load_wait && !e.observer_host && age_ms < hold::kLoadDeferMaxMs;
    if (!r.actor) {
        return stale && !load_hold ? out(ReleaseStep::Drop, "stale (actor unreadable for too long)", NpcRelease::None)
                                   : out(ReleaseStep::Keep, "actor unreadable", NpcRelease::None);
    }
    if (!*r.actor) return out(ReleaseStep::Drop, "despawned", NpcRelease::None);
    if (!r.observer_valid) return out(ReleaseStep::Drop, "observer gone", NpcRelease::None);
    if (r.observer_user != e.observer_user) {
        return out(ReleaseStep::Drop, "observer's user changed", NpcRelease::None);
    }
    if (r.observes && !*r.observes) {
        if (load_hold) {
            return out(ReleaseStep::Keep, "user 2 is still loading (observer_load_defer), not in range now",
                       NpcRelease::None);
        }
        // Left the field or the actor's sectors: the engine announces it again
        // when it comes back in range (and it is held again if still at 0).
        return out(ReleaseStep::Drop, "observer out of range", NpcRelease::None);
    }
    if (load_hold) {
        return out(ReleaseStep::Keep, "user 2 is still loading (observer_load_defer)", NpcRelease::None);
    }
    // From here the actor exists and the observer is valid. Whatever would have
    // dropped the entry while the observer still observes the actor announces
    // it natively instead: an entry dropped in range left the NPC invisible.
    const bool in_range = r.observes.value_or(false);
    auto keep = [&](const char* w) {
        if (!stale) return out(ReleaseStep::Keep, w, NpcRelease::None);
        return in_range ? out(ReleaseStep::Release, "unreadable for too long: announced natively", NpcRelease::Native)
                        : out(ReleaseStep::Drop, "stale (unreadable for too long)", NpcRelease::None);
    };
    if (e.actor && *r.actor != e.actor) {
        if (!in_range) return keep("another actor behind the key; observers unreadable");
        return out(ReleaseStep::Release, "another actor behind the key: announced natively", NpcRelease::Native);
    }
    if (!r.owner) return keep("owner unreadable");
    if (*r.owner != 0) {
        // Now a user's child (D-53's case).
        if (r.restore && *r.restore == 1) {
            if (!in_range) return keep("now owned by a user, restore 1; observers unreadable");
            return out(ReleaseStep::Release, "now owned by a user, restore 1", NpcRelease::Restore1);
        }
        if (!children_rule) {
            if (!in_range) return keep("now owned by a user (child_hold off); observers unreadable");
            return out(ReleaseStep::Release, "now owned by a user (child_hold off): announced natively",
                       NpcRelease::Native);
        }
        // child_hold: a user's child is never announced to another user with restore 0.
        if (stale) {
            return out(ReleaseStep::Drop, "now owned by a user and still restore 0 (D-53: never with 0)",
                       NpcRelease::None);
        }
        return out(ReleaseStep::Keep, "now owned by a user, restore 0 (D-53: waits for its first action)",
                   NpcRelease::None);
    }
    if (!r.controller) return keep("controller unreadable");
    const bool observer_controls = r.observer_key && *r.controller == r.observer_key;
    if (!observer_controls) {
        if (!r.restore) return keep("restore byte unreadable");
        if (*r.restore != 1) {
            // Seen live (2026-10-09): ambient creatures (type 6, e.g. a ringneck)
            // get StartActionReq from the host's client again and again and still
            // serialise restore 0, so "restore 1" never comes for them. After the
            // timeout they are announced as the engine would (restore 0) and their
            // actions reach the observer by StartActionAck 2991 (guest_s3 shows
            // whether one gets installed; guest_update_guard contains the window).
            if (std::min(age_ms, r.timeout_age_ms) >= hold::kNpcTimeoutMs) {
                // P8 U-e (the 6c12c82 crash): never to the HOST with restore 0 while user 2 controls it. It waits
                // for restore 1 (user 2's first accepted action), for the host to become its controller, or for a
                // drop above (another epoch, despawned, observer gone or out of range); no stale drop here.
                if (e.observer_host && r.user2_key && *r.controller == r.user2_key) {
                    return out(ReleaseStep::Keep, "withheld from the host: user 2 controls it, restore 0",
                               NpcRelease::WithheldUser2);
                }
                if (!in_range) return keep("timeout; observers unreadable");
                return out(ReleaseStep::Release, "timeout: released with restore 0 (no restorable first action)",
                           NpcRelease::Timeout);
            }
            return out(ReleaseStep::Keep, *r.controller != e.controller ? "restore 0 (controller changed)" : "restore 0",
                       NpcRelease::None);
        }
    }
    if (!r.observes) return keep("observers unreadable");
    return observer_controls
               ? out(ReleaseStep::Release, "the observer is now its controller", NpcRelease::ByControl)
               : out(ReleaseStep::Release, "restore 1", NpcRelease::Restore1);
}

CharReleaseReadings read_char_release(uintptr_t sam, uint32_t key, uintptr_t observer_user) {
    const game::FastReads m;
    CharReleaseReadings r;
    r.actor = find_actor_with(m, sam, key);
    if (!r.actor || !*r.actor) return r;
    const uintptr_t actor = *r.actor;
    r.owner = m.rd<uintptr_t>(actor + hold::kActorOwner);
    r.restore = restore_byte_with(m, actor);
    if (const auto sector = sector_with(m, actor)) r.observes = observed_by_with(m, *sector, observer_user);
    return r;
}

const char* char_release_name(CharRelease k) {
    switch (k) {
        case CharRelease::None: return "-";
        case CharRelease::Restore1: return "restore 1";
        case CharRelease::Timeout: return "TIMEOUT, announced with restore 0";
        case CharRelease::Native: return "announced natively instead of dropped";
    }
    return "?";
}

ReleaseStep char_release_step(const HoldEntry& e, const CharReleaseReadings& r, uint64_t age_ms, const char*& why,
                              CharRelease* kind) {
    auto out = [&](ReleaseStep s, const char* w, CharRelease k) {
        why = w;
        if (kind) *kind = k;
        return s;
    };
    if (r.epoch_now != e.epoch) return out(ReleaseStep::Drop, "another guest epoch", CharRelease::None);
    const bool stale = age_ms >= 3 * hold::kCharTimeoutMs;
    if (!r.actor) {
        return stale ? out(ReleaseStep::Drop, "stale (actor unreadable for too long)", CharRelease::None)
                     : out(ReleaseStep::Keep, "actor unreadable", CharRelease::None);
    }
    if (!*r.actor) return out(ReleaseStep::Drop, "despawned (logout or gone)", CharRelease::None);
    if (!r.observer_valid || r.observer_user != e.observer_user) {
        return out(ReleaseStep::Drop, "observer gone", CharRelease::None);
    }
    if (r.observes && !*r.observes) {
        // A field change (either side) or the sectors left: the engine announces
        // it again when it comes back in range (and it is held again if still 0).
        return out(ReleaseStep::Drop, "observer out of range", CharRelease::None);
    }
    const bool in_range = r.observes.value_or(false);
    auto keep = [&](const char* w) {
        if (!stale) return out(ReleaseStep::Keep, w, CharRelease::None);
        return in_range ? out(ReleaseStep::Release, "unreadable for too long: announced natively", CharRelease::Native)
                        : out(ReleaseStep::Drop, "stale (unreadable for too long)", CharRelease::None);
    };
    if (e.actor && *r.actor != e.actor) {
        if (!in_range) return keep("another actor behind the key; observers unreadable");
        return out(ReleaseStep::Release, "another actor behind the key: announced natively", CharRelease::Native);
    }
    if (!r.owner) return keep("owner unreadable");
    if (*r.owner != e.owner) {
        if (!in_range) return keep("owner changed; observers unreadable");
        return out(ReleaseStep::Release, "owner changed: announced natively", CharRelease::Native);
    }
    if (!r.restore) return keep("restore byte unreadable");
    if (*r.restore == 1) {
        if (!in_range) return keep("restore 1; observers unreadable");
        return out(ReleaseStep::Release, "restore 1", CharRelease::Restore1);
    }
    if (age_ms >= hold::kCharTimeoutMs) {
        if (!in_range) return keep("timeout; observers unreadable");
        return out(ReleaseStep::Release, "timeout: announced with restore 0 (no first action accepted)",
                   CharRelease::Timeout);
    }
    return out(ReleaseStep::Keep, "restore 0", CharRelease::None);
}

std::optional<uint32_t> start_action_req_key(uintptr_t ctx) {
    const auto size = game::fast<uint16_t>(ctx + hold::kReqWrapperSize);
    const auto raw = game::fast_ptr(ctx + hold::kReqWrapperRaw);
    if (!size || !raw) return std::nullopt;
    const auto len = game::fast<uint16_t>(*raw + hold::kReqRawLen);
    // vf2's own test (0x296CAA0): wrapper size - 5 == the raw length; a key needs 4 bytes.
    if (!len || *size < hold::kReqRawPayload || *size - hold::kReqRawPayload != *len || *len < 4) {
        return std::nullopt;
    }
    return game::fast<uint32_t>(*raw + hold::kReqRawPayload);
}

ReleaseReadings read_child_release(uintptr_t sam, uint32_t key, uintptr_t observer_user) {
    ReleaseReadings r;
    r.actor = sam_find_actor(sam, key);
    if (!r.actor) r.actor = sam_find_actor(sam, key);
    if (!r.actor || !*r.actor) return r;
    const uintptr_t actor = *r.actor;
    r.owner = read<uintptr_t>(actor + hold::kActorOwner);
    r.restore = child_restore_byte(actor);
    if (const auto sector = child_sector(actor)) r.observes = sector_observed_by(*sector, observer_user);
    return r;
}

ReleaseStep release_step(const HoldEntry& e, const ReleaseReadings& r, const char*& why) {
    if (r.epoch_now != e.epoch) {
        why = "another guest epoch";
        return ReleaseStep::Drop;
    }
    if (!r.actor) {
        why = "child unreadable";
        return ReleaseStep::Keep;
    }
    if (!*r.actor) {
        why = "child gone";
        return ReleaseStep::Drop;
    }
    if (!r.owner) {
        why = "owner unreadable";
        return ReleaseStep::Keep;
    }
    if (*r.owner != e.owner) {
        why = "owner changed";
        return ReleaseStep::Drop;
    }
    if (!r.restore) {
        why = "restore byte unreadable";
        return ReleaseStep::Keep;
    }
    if (*r.restore != 1) {
        why = "restore 0";  // never released without its first action
        return ReleaseStep::Keep;
    }
    if (!r.observer_valid || r.observer_user != e.observer_user) {
        why = "observer gone";
        return ReleaseStep::Drop;
    }
    if (!r.observes) {
        why = "observers unreadable";
        return ReleaseStep::Keep;
    }
    if (!*r.observes) {
        // The engine announces it again when the observer comes back in
        // range (and holds it again here if it still had restore 0).
        why = "observer out of range";
        return ReleaseStep::Drop;
    }
    why = "restore 1";
    return ReleaseStep::Release;
}

// ------------------------------------------------------------------ the game side

namespace {

// Entries and body instructions checked against the copy analysed for D-53
// (prologues alone repeat; companeros-publicacion.md §1.2-§1.3, §2).
constexpr uintptr_t kNotifyAppear = 0x2B000C0;
constexpr uint8_t kNotifyAppearHead[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x48, 0x89, 0x7C, 0x24,
                                         0x18, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48,
                                         0x83, 0xEC, 0x50, 0x4D, 0x8B, 0xF8, 0x48, 0x8B, 0xF2, 0x45, 0x33, 0xE4};
constexpr uintptr_t kNotifyReadSessions = 0x2B001B7;  // mov rbx,[rsi] ; mov eax,[rsi+8]
constexpr uint8_t kNotifyReadSessionsBytes[] = {0x48, 0x8B, 0x1E, 0x8B, 0x46, 0x08};
constexpr uintptr_t kNotifyReadKeys = 0x2B0021D;  // mov rax,[r15] ; mov [rbp-0x10],rax ; mov eax,[r15+8]
constexpr uint8_t kNotifyReadKeysBytes[] = {0x49, 0x8B, 0x07, 0x48, 0x89, 0x45, 0xF0, 0x41, 0x8B, 0x47, 0x08};
constexpr uintptr_t kNotifyFindCall = 0x2B00233;  // call 0x2B060E0 (keys -> actors, owner filter)
constexpr uint8_t kNotifyFindCallBytes[] = {0xE8, 0xA8, 0x5E, 0x00, 0x00};
constexpr uintptr_t kCallerNewObservers = 0x2AF90EB;  // call 0x2B000C0
constexpr uint8_t kCallerNewObserversBytes[] = {0xE8, 0xD0, 0x6F, 0x00, 0x00};
constexpr uintptr_t kCallerMovingUser = 0x2AF92D1;  // call 0x2B000C0
constexpr uint8_t kCallerMovingUserBytes[] = {0xE8, 0xEA, 0x6D, 0x00, 0x00};
constexpr uintptr_t kStartAction = 0x296CAA0;  // TrocTrStartActionReq::vf2 (this, int* res, ctx*) -> res
constexpr uint8_t kStartActionHead[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
                                        0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0xD0, 0xFC, 0xFF, 0xFF, 0x48, 0x81, 0xEC, 0x40,
                                        0x04, 0x00, 0x00, 0x4D, 0x8B, 0xE0, 0x48, 0x8B, 0xF2, 0x4C, 0x8B, 0xF9};
constexpr uintptr_t kStartActionVtable = 0x5B251D8;  // .?AVTrocTrStartActionReq@pa@@, vf2 at +0x10
constexpr uintptr_t kRestoreWrite = 0x2328890;  // mov rax,[r14+0x40] ; mov byte [rax+0x30],1 (the only writer)
constexpr uint8_t kRestoreWriteBytes[] = {0x49, 0x8B, 0x46, 0x40, 0xC6, 0x40, 0x30, 0x01};
// ServerRunThread's entry 0x2773390 marks its thread as the server's realm
// (TLS block 0 +0x1EC = 1) before its loop; NotifyAppear's key lookup picks the
// server's actor manager by that byte (0x2B06147).
constexpr uintptr_t kServerRealmSet = 0x27733A6;  // mov eax,0x1EC ; mov byte [rax+rbx],1
constexpr uint8_t kServerRealmSetBytes[] = {0xB8, 0xEC, 0x01, 0x00, 0x00, 0xC6, 0x04, 0x18, 0x01};
constexpr uint32_t kTlsServerRealm = 0x1EC;

// Build 3527: verified native callers, RTTI vf2, restore writer and TLS realm
// are recorded in tools/porting/data/child_hold_3527.json. These are function
// entry hooks; the remaining sites below are read-only semantic checks.
constexpr uint8_t kNotifyAppearHead3527[] = {
    0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x74,0x24,0x10,0x48,0x89,0x7C,0x24,
    0x18,0x55,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x8B,0xEC,0x48,
    0x83,0xEC,0x50,0x4D,0x8B,0xE0,0x4C,0x8B,0xF2,0x45,0x33,0xED};
constexpr uint8_t kStartActionHead3527[] = {
    0x48,0x89,0x5C,0x24,0x08,0x55,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,
    0x41,0x57,0x48,0x8D,0xAC,0x24,0xD0,0xFC,0xFF,0xFF,0x48,0x81,0xEC,0x40,
    0x04,0x00,0x00,0x4D,0x8B,0xE0,0x4C,0x8B,0xF2,0x4C,0x8B,0xF9};
constexpr uint8_t kNotifyReadSessionsBytes3527[] = {0x49,0x8B,0x1E,0x41,0x8B,0x46,0x08};
constexpr uint8_t kNotifyReadKeysBytes3527[] = {
    0x49,0x8B,0x04,0x24,0x48,0x89,0x45,0xF0,0x41,0x8B,0x44,0x24,0x08};
constexpr uint8_t kNotifyFindCallBytes3527[] = {0xE8,0x8C,0x84,0x00,0x00};
constexpr uint8_t kCallerNewObserversBytes3527[] = {0xE8,0x20,0x78,0x00,0x00};
constexpr uint8_t kCallerMovingUserBytes3527[] = {0xE8,0x1F,0x76,0x00,0x00};
constexpr uint8_t kRestoreWriteBytes3527[] = {0x49,0x8B,0x47,0x40,0xC6,0x40,0x30,0x01};
constexpr uint8_t kServerRealmSetBytes3527[] = {0xB8,0xEB,0x01,0x00,0x00,0xC6,0x04,0x18,0x01};

struct HoldCodeCheck {
    uintptr_t rva;
    std::span<const uint8_t> bytes;
    const char* what;
};
constexpr HoldCodeCheck kHoldChecks2976[] = {
    {kNotifyAppear, kNotifyAppearHead, "NotifyAppear"},
    {kNotifyReadSessions, kNotifyReadSessionsBytes, "NotifyAppear's session vector"},
    {kNotifyReadKeys, kNotifyReadKeysBytes, "NotifyAppear's key vector"},
    {kNotifyFindCall, kNotifyFindCallBytes, "NotifyAppear's key lookup"},
    {kCallerNewObservers, kCallerNewObserversBytes, "OnActorSectorChanged's first call"},
    {kCallerMovingUser, kCallerMovingUserBytes, "OnActorSectorChanged's second call"},
    {kStartAction, kStartActionHead, "StartActionReq::vf2"},
    {kRestoreWrite, kRestoreWriteBytes, "the restore byte's writer"},
    {kServerRealmSet, kServerRealmSetBytes, "ServerRunThread's realm mark"}};
constexpr HoldCodeCheck kHoldChecks3527[] = {
    {0x2D96BB0, kNotifyAppearHead3527, "NotifyAppear"},
    {0x2D96CBC, kNotifyReadSessionsBytes3527, "NotifyAppear's session vector"},
    {0x2D96D27, kNotifyReadKeysBytes3527, "NotifyAppear's key vector"},
    {0x2D96D3F, kNotifyFindCallBytes3527, "NotifyAppear's key lookup"},
    {0x2D8F38B, kCallerNewObserversBytes3527, "OnActorSectorChanged's first call"},
    {0x2D8F58C, kCallerMovingUserBytes3527, "OnActorSectorChanged's second call"},
    {0x2BE08C0, kStartActionHead3527, "StartActionReq::vf2"},
    {0x251905A, kRestoreWriteBytes3527, "the restore byte's writer"},
    {0x29AAF36, kServerRealmSetBytes3527, "ServerRunThread's realm mark"}};
// Build 1.0.0.3576 (static, 2026-11-06; not yet run). Every site moved with its whole function (.pdata begins at old +
// shift with 3527's size) and keeps 3527's bytes, so the 3527 arrays check it as they are (their rel32 are internal or
// to functions that moved by the same shift):
//   NotifyAppear 0x2D96BB0 -> 0x2D97820 (+0xC70, 0x31F bytes), its key finder 0x2D9F1D0 -> 0x2D9FE40 (+0xC70, the call
//     at 0x2D979AF keeps E8 8C 84 00 00, the finder still takes TLS block 0 +0x1EB at 0x2D9FE7B);
//   OnActorSectorChanged 0x2D8ED90 -> 0x2D8FA00 (+0xC70, 0xFED bytes): the exe's only rel32 calls to 0x2D97820 are its
//     0x2D8FFFB and 0x2D901FC (3527's two + 0xC70, same bytes); sector observers +0x68/+0x70/16 and owner +0xA0 read
//     with 3527's bytes at 0x2D8FBAF / 0x2D8FBCB / 0x2D90345;
//   StartActionReq::vf2 0x2BE08C0 -> 0x2BE1530 (+0xC70, 0x6D8 bytes) = slot 2 of .?AVTrocTrStartActionReq@pa@@'s
//     vtable 0x5EEE318 (3527's 0x5EEC638, RTTI / vtable_map_3549_3576.json); its info +0x88/+1, components +0x68 and
//     CC +0x40 reads and the action logic's CC +8 / controller +0x90 (0x2D081C2 / 0x2D081EF) have 3527's bytes;
//   the restore writer 0x251905A -> 0x2519E2A (+0xDD0; function 0x2518850, 0x1E33 bytes);
//   ServerRunThread's realm mark 0x29AAF36 -> 0x29ABB86 (+0xC50; function 0x29ABB70, 0x5C bytes): gs:[0x58] -> [rax]
//     -> +0x1EB = 1, the same TLS byte as 3527;
//   the ServerActorManager's vf4 (vtable 0x5EEF0A8) 0x2D11880 keeps the map at +0x98/+0x9C/+0xA8/+0xB0, holder +4/+8.
constexpr HoldCodeCheck kHoldChecks3576[] = {
    {0x2D97820, kNotifyAppearHead3527, "NotifyAppear"},
    {0x2D9792C, kNotifyReadSessionsBytes3527, "NotifyAppear's session vector"},
    {0x2D97997, kNotifyReadKeysBytes3527, "NotifyAppear's key vector"},
    {0x2D979AF, kNotifyFindCallBytes3527, "NotifyAppear's key lookup"},
    {0x2D8FFFB, kCallerNewObserversBytes3527, "OnActorSectorChanged's first call"},
    {0x2D901FC, kCallerMovingUserBytes3527, "OnActorSectorChanged's second call"},
    {0x2BE1530, kStartActionHead3527, "StartActionReq::vf2"},
    {0x2519E2A, kRestoreWriteBytes3527, "the restore byte's writer"},
    {0x29ABB86, kServerRealmSetBytes3527, "ServerRunThread's realm mark"}};
// Build 1.0.0.3663 (static, 2026-11-13; never run). Every site found again inside the same function (.pdata, 3576's
// sizes), with 3527's bytes except three rel32 (new arrays below):
//   NotifyAppear 0x2D96BB0 -> 0x2DFE6D0 (+0x67B20, 0x31F bytes; head, session and key vectors with 3527's bytes); its key
//     finder 0x2D9F1D0 -> 0x2E06E00 (+0x67C30, so the call at 0x2DFE85F is now E8 9C 85 00 00; the finder still takes
//     TLS block 0 +0x1EB at 0x2E06E3B);
//   OnActorSectorChanged 0x2D8ED90 -> 0x2DF67A0 (+0x67A10, 0xFED bytes): the exe's only rel32 calls to 0x2DFE6D0 are its
//     0x2DF6D9B and 0x2DF6F9C (3527's +0x5FB / +0x7FC, new rel32); sector observers +0x68/+0x70 (0x2DF694F / 0x2DF6953)
//     and owner +0xA0 (0x2DF70E5) read as on 3527;
//   StartActionReq::vf2 0x2BE08C0 -> 0x2C46FA0 (+0x666E0, 0x6D8 bytes) = slot 2 of .?AVTrocTrStartActionReq@pa@@'s vtable
//     0x5F682B8 (3576's 0x5EEE318, vtable_map_3576_3663.json); info +0x88 (0x2C473BB), components +0x68 (0x2C47416) and
//     CC +0x40 (0x2C4743D) read as on 3527;
//   the restore writer 0x251905A -> 0x258B7AA (+0x72750; in 0x258A230, which is 0x60 bytes shorter than on 3576; the
//     8 bytes are unique in the code section: `mov rax,[r15+0x40] ; mov byte [rax+0x30],1`);
//   ServerRunThread's realm mark 0x29AAF36 -> 0x2A0E1B6 (+0x63280; function 0x2A0E1A0, 0x5C bytes): TLS +0x1EB = 1;
//   TransformSync sector +0x548: ToNearExceptOneControl / ToNearExceptOneSelf vf1 (0x2D6C360 / 0x2D6C230, profile_s2.h)
//     read [TS+0x548] at 0x2D6C3E0 / 0x2D6C2B0 after TS = [components+0x1A0].
// Not re-derived on 3663: the action logic's controller +0x90 (child_hold.h kActorController).
constexpr uint8_t kNotifyFindCallBytes3663[] = {0xE8, 0x9C, 0x85, 0x00, 0x00};      // 0x2DFE85F: call 0x2E06E00
constexpr uint8_t kCallerNewObserversBytes3663[] = {0xE8, 0x30, 0x79, 0x00, 0x00};  // 0x2DF6D9B: call 0x2DFE6D0
constexpr uint8_t kCallerMovingUserBytes3663[] = {0xE8, 0x2F, 0x77, 0x00, 0x00};    // 0x2DF6F9C: call 0x2DFE6D0
constexpr HoldCodeCheck kHoldChecks3663[] = {
    {0x2DFE6D0, kNotifyAppearHead3527, "NotifyAppear"},
    {0x2DFE7DC, kNotifyReadSessionsBytes3527, "NotifyAppear's session vector"},
    {0x2DFE847, kNotifyReadKeysBytes3527, "NotifyAppear's key vector"},
    {0x2DFE85F, kNotifyFindCallBytes3663, "NotifyAppear's key lookup"},
    {0x2DF6D9B, kCallerNewObserversBytes3663, "OnActorSectorChanged's first call"},
    {0x2DF6F9C, kCallerMovingUserBytes3663, "OnActorSectorChanged's second call"},
    {0x2C46FA0, kStartActionHead3527, "StartActionReq::vf2"},
    {0x258B7AA, kRestoreWriteBytes3527, "the restore byte's writer"},
    {0x2A0E1B6, kServerRealmSetBytes3527, "ServerRunThread's realm mark"}};
struct ChildHoldProfile {
    uintptr_t notify, action, action_vtable, caller_new, caller_moving;
    uint32_t tls_realm;
    std::span<const HoldCodeCheck> checks;
};
const ChildHoldProfile* child_hold_profile() noexcept {
    static constexpr ChildHoldProfile old{kNotifyAppear, kStartAction, kStartActionVtable,
        kCallerNewObservers, kCallerMovingUser, kTlsServerRealm, kHoldChecks2976};
    static constexpr ChildHoldProfile current{0x2D96BB0, 0x2BE08C0, 0x5EEC638,
        0x2D8F38B, 0x2D8F58C, 0x1EB, kHoldChecks3527};
    // 3576 (static, 2026-11-06; not yet run): kHoldChecks3576 above.
    static constexpr ChildHoldProfile current3576{0x2D97820, 0x2BE1530, 0x5EEE318,
        0x2D8FFFB, 0x2D901FC, 0x1EB, kHoldChecks3576};
    // Build 1.0.0.3663 (static, 2026-11-13; never run): kHoldChecks3663 above.
    static constexpr ChildHoldProfile current3663{0x2DFE6D0, 0x2C46FA0, 0x5F682B8,
        0x2DF6D9B, 0x2DF6F9C, 0x1EB, kHoldChecks3663};
    switch (game::current_build()) {
        case game::Build::v2976: return &old;
        case game::Build::v3527: return &current;
        case game::Build::v3576: return &current3576;
        case game::Build::v3663: return &current3663;
        default: return nullptr;
    }
}
const ChildHoldProfile* g_profile = nullptr;

constexpr uint32_t kMaxKeys = 0x4000;      // larger lists go unchanged
constexpr uint32_t kMaxSessions = 64;
constexpr uint64_t kTickMs = 50;
constexpr uint64_t kMaxHoldLogged = 32, kMaxReleaseLogged = 32, kMaxOtherLogged = 32;

uintptr_t g_base = 0;
SafetyHookInline g_notify, g_action;
std::atomic<bool> g_active{false};
std::mutex g_mu;
HoldTable g_table;                     // under g_mu
std::atomic<size_t> g_size{0};         // g_table.size(), read without the lock
std::atomic<uint32_t> g_host_key{0};   // last host user key read
std::atomic<uint64_t> g_last_tick{0};

std::atomic<uint64_t> g_calls{0}, g_split{0}, g_unreadable{0}, g_not_realm{0}, g_held{0}, g_held_again{0},
    g_held_host{0}, g_held_user2{0}, g_unrecorded{0}, g_owner_sent{0}, g_owner_absent{0}, g_released{0},
    g_dropped{0}, g_cleared{0},
    g_timeouts{0}, g_forgotten{0}, g_errors{0}, g_sweep_other{0}, g_action_calls{0}, g_hold_logged{0},
    g_release_logged{0}, g_other_logged{0};

// observer_hold (S3). Everything below stays idle (and its table empty) with observer_hold=0.
std::atomic<bool> g_children{true};    // D-53's rule (child_hold)
std::atomic<bool> g_observers{false};  // S3's rule (observer_hold)
// S33 (npc_activation / npc_family_control not 0): prepare_family also reads the withheld keys' parent for the probes.
std::atomic<bool> g_npc_family_observe{false};
NpcHoldTable g_npc_table;              // under g_mu
size_t g_npc_reserved = 0;             // under g_mu: room promised to splits not recorded yet
size_t g_npc_cursor = 0;               // under g_mu: where the next budgeted pass starts
std::atomic<size_t> g_npc_size{0};
std::atomic<uint64_t> g_npc_held{0}, g_npc_held_host_ctrl{0}, g_npc_held_user2_ctrl{0}, g_npc_again{0},
    g_npc_full{0}, g_npc_unrecorded{0}, g_npc_released{0}, g_npc_released_ctrl{0}, g_npc_dropped{0},
    g_npc_timeouts{0}, g_npc_withheld_u2{0}, g_npc_timeout_host_u2{0}, g_npc_native{0}, g_npc_forgotten{0}, g_npc_cleared{0}, g_npc_ctrl_changed{0},
    g_npc_release_calls{0}, g_npc_deferred{0}, g_npc_busy_skips{0}, g_npc_targeted{0}, g_npc_periodic{0},
    g_npc_evaluated{0}, g_npc_pass_us_sum{0}, g_npc_pass_us_max{0}, g_prepare_us_max{0}, g_npc_hold_logged{0},
    g_npc_release_logged{0}, g_npc_other_logged{0};
std::atomic<uint64_t> g_npc_age_sum{0}, g_npc_age_max{0};  // ms, of the released ones
std::atomic<uint64_t> g_npc_last_pass{0}, g_npc_last_fallback{0};
constexpr uint64_t kMaxNpcHoldLogged = 48, kMaxNpcReleaseLogged = 48, kMaxNpcOtherLogged = 64;
// observer_load_defer (P8 session 14). Idle with the key at 0 (and with observer_hold=0).
std::atomic<uint8_t> g_load_defer{0};       // u2f::Mode: 0 off, 1 probe, 2 on
std::atomic<bool> g_user2_loading{false};   // user 2's move phase is 2549 .. 2762 (server.cpp)
// P8 S14 review M1/L2: when the current load began (0 = none) and when the last one ended (its 2762, or the cap).
std::atomic<uint64_t> g_load_start_ms{0}, g_load_end_ms{0};
std::atomic<bool> g_load_stuck_noted{false};
std::atomic<uint64_t> g_ld_deferred{0}, g_ld_would{0}, g_ld_released{0}, g_ld_cap{0}, g_ld_dropped{0},
    g_ld_wait_sum{0}, g_ld_wait_max{0}, g_ld_kept{0}, g_ld_logged{0}, g_ld_rel_logged{0}, g_ld_loads{0},
    g_ld_phase_logged{0}, g_ld_drop_despawned{0}, g_ld_drop_gone{0}, g_ld_drop_other{0}, g_ld_stuck{0};
constexpr uint64_t kMaxLoadPhaseLogged = 32;
// observer_hold_family (pendientes/p8-s14-viajeros.md §7). Idle with the key at 0 (and with observer_hold=0).
std::atomic<uint8_t> g_family{0};           // u2f::Mode: 0 off, 1 probe, 2 on
FamilyHoldTable g_fam_table;                // under g_mu
size_t g_fam_reserved = 0;                  // under g_mu: room promised to splits not recorded yet
std::atomic<size_t> g_fam_size{0};
// What user 2's live session 2 has been given (NotifyAppear to it, take_frame's 2005 to it) and not removed
// since (2516): its session and guest epoch, under g_mu. Only with the key at probe or 1.
fam::KeySet<hold::kFamilyKnownSlots> g_known;
uintptr_t g_known_session = 0;
uint32_t g_known_epoch = 0;
std::atomic<uint64_t> g_fm_seen{0}, g_fm_would{0}, g_fm_held{0}, g_fm_again{0}, g_fm_full{0}, g_fm_partial{0},
    g_fm_unlinked{0}, g_fm_released{0}, g_fm_orphans{0}, g_fm_dropped{0}, g_fm_cleared{0}, g_fm_forgotten{0},
    g_fm_unrecorded{0}, g_fm_max_age{0}, g_fm_deferred{0}, g_fm_age_max{0}, g_fm_logged{0}, g_fm_rel_logged{0},
    g_fm_other_logged{0}, g_fm_with_parent{0}, g_fm_after_parent{0}, g_fm_orphan_timeouts{0}, g_fm_converted{0},
    g_fm_blocked_native{0}, g_fm_would_block{0}, g_fm_held_unknown{0}, g_fm_held_in_call{0}, g_fm_held_held{0},
    g_fm_known_overflow{0}, g_fm_ac_same{0}, g_fm_ac_other{0}, g_fm_ac_only{0}, g_fm_ac_logged{0},
    g_fm_tail_calls{0};
// The safety valve: when members waiting for a parent user 2 never gets time out too often (the hierarchy names
// parents the engine does not send: then every such member would just be late), the "not announced yet" rule
// switches itself off for the session (the parent-withheld rules stay). Never back on until reset.
std::atomic<bool> g_fm_unknown_off{false};
std::atomic<uint64_t> g_fm_valve_logged{0};
constexpr uint64_t kFamUnknownValveMin = 16;  // timeouts before the valve may trip
constexpr uint64_t kFamUnknownValveDiv = 4;   // ... and more than 1 in 4 of those withheld for that reason
constexpr uint64_t kMaxFamLogged = 48, kMaxFamRelLogged = 48, kMaxFamOtherLogged = 32, kMaxFamAcLogged = 12;
// take_frame's mirror of analyze_capture.py `orphans` for user 2 (with observer_hold=1, whatever the family key).
std::mutex g_out_mu;
fam::OrphanCounter<hold::kFamilyKnownSlots> g_out_count;  // under g_out_mu
uint32_t g_out_epoch = 0;                                 // under g_out_mu
std::atomic<uint64_t> g_out_records{0}, g_out_orphans{0}, g_out_2005{0}, g_out_2516{0}, g_out_2174{0},
    g_out_logged{0};
constexpr uint64_t kMaxOutOrphanLogged = 40;

// S35 publication_gate (publication_gate_logic.h). Idle with the key at 0 (and with observer_hold=0).
std::atomic<uint8_t> g_pub_gate{0};                 // u2f::Mode / pubg::Mode: 0 off, 1 probe, 2 on
std::atomic<uint64_t> g_pub_retain_ms{60000};
std::atomic<uint64_t> g_pg_evaluated{0}, g_pg_published{0}, g_pg_gone{0}, g_pg_would{0}, g_pg_retained{0},
    g_pg_dropped_expired{0}, g_pg_dropped_no_room{0}, g_pg_withheld_no_entry{0}, g_pg_would_no_entry{0},
    g_pg_cc_unknown_held{0}, g_pg_cc_unknown_would{0}, g_pg_retain_max_ms{0}, g_pg_logged{0}, g_pg_drop_logged{0},
    g_pg_entry_logged{0};
std::atomic<uint64_t> g_pg_by_verdict[static_cast<size_t>(pubg::Verdict::Count)] = {};
constexpr uint64_t kMaxPubLogged = 64, kMaxPubDropLogged = 64, kMaxPubEntryLogged = 32;
// Revisión S35: devoluciones fusionadas con una retención fresca (6), miembros arrastrados por un padre soltado sin
// publicar (7), salidas sin comprobar porque prepare() no pudo (11: SAM ilegible, sesión ilegible, excepción), y el
// registro sombra de probe (4): lo que se habría retenido y si se habría recuperado dentro de la retención.
std::atomic<uint64_t> g_pg_merged{0}, g_pg_members_dragged{0}, g_pg_unchecked_sam{0}, g_pg_unchecked_session{0},
    g_pg_unchecked_error{0}, g_pg_unchecked_logged{0}, g_pg_shadow_recorded{0}, g_pg_shadow_full{0},
    g_pg_shadow_recovered{0}, g_pg_shadow_would_drop{0}, g_pg_shadow_gone{0}, g_pg_shadow_recover_max_ms{0};
std::atomic<size_t> g_pub_shadow_size{0};  // probe shadow records pending (lock-free copy of g_pub_shadow_n)
pubg::Mode pub_gate() { return static_cast<pubg::Mode>(g_pub_gate.load(std::memory_order_relaxed)); }
// Review 11: a NotifyAppear the gate could not evaluate goes out unchanged (as before). Counted and logged (WRN,
// bounded). Its retained entries are then forgotten by forget(): the engine has just announced them itself.
constexpr uint64_t kMaxPubUncheckedLogged = 16;
void pub_unchecked(uint64_t why, size_t nkeys);

// character_hold. Everything below stays idle (and its table empty) with character_hold=0.
std::atomic<bool> g_characters{false};
CharHoldTable g_char_table;            // under g_mu
size_t g_char_reserved = 0;            // under g_mu: room promised to splits not recorded yet
std::atomic<size_t> g_char_size{0};
std::atomic<uint64_t> g_char_held{0}, g_char_held_host{0}, g_char_held_user2{0}, g_char_again{0}, g_char_full{0},
    g_char_unrecorded{0}, g_char_released{0}, g_char_restore1{0}, g_char_timeouts{0}, g_char_native{0},
    g_char_dropped{0}, g_char_cleared{0}, g_char_forgotten{0}, g_char_deferred{0}, g_char_not_main{0},
    g_char_age_max{0}, g_char_hold_logged{0}, g_char_release_logged{0}, g_char_other_logged{0};
std::atomic<uint64_t> g_char_last_pass{0}, g_char_last_fallback{0}, g_child_tail_tick{0};
constexpr uint64_t kMaxCharHoldLogged = 32, kMaxCharReleaseLogged = 32, kMaxCharOtherLogged = 32;

// child_settle (P8 session 8 pets). Everything below stays idle (its table and log empty) with child_settle_ms=0.
std::atomic<uint32_t> g_settle_ms{0};
SettleHoldTable g_settle_table;        // under g_mu
size_t g_settle_reserved = 0;          // under g_mu: room promised to splits not recorded yet
std::atomic<size_t> g_settle_size{0};
cst::AnnounceLog<hold::kAnnounceLogSlots> g_announced;  // (0xA key, session) -> last announcement (lock-free)
std::atomic<uint64_t> g_settle_held{0}, g_settle_held_host{0}, g_settle_held_user2{0}, g_settle_again{0},
    g_settle_full{0}, g_settle_unrecorded{0}, g_settle_released{0}, g_settle_settled{0}, g_settle_max_wait{0},
    g_settle_native{0}, g_settle_dropped{0}, g_settle_cleared{0}, g_settle_forgotten{0}, g_settle_deferred{0},
    g_settle_d53_waited{0}, g_settle_announced{0}, g_settle_age_max{0}, g_settle_hold_logged{0},
    g_settle_release_logged{0}, g_settle_other_logged{0}, g_settle_raced{0}, g_settle_fallback{0};
std::atomic<uint64_t> g_settle_last_pass{0}, g_settle_last_fallback{0};
constexpr uint64_t kMaxSettleHoldLogged = 32, kMaxSettleReleaseLogged = 32, kMaxSettleOtherLogged = 32;

// The thread rule (p8-auditoria-hilos.md §4 case 3): the threads the game itself
// used for NotifyAppear (filled left to right, never emptied in a process).
std::array<std::atomic<uint32_t>, hold::kNativeThreads> g_native_tids{};
std::atomic<uint64_t> g_native_count{0}, g_native_full{0}, g_notify_foreign{0}, g_child_deferred{0},
    g_npc_thread_deferred{0}, g_native_logged{0};
// [session2] notify_thread_rule (P8 review I3): 0 (default) = the threads as before the rule.
std::atomic<bool> g_thread_rule{false};
// The last thread that called NotifyAppear (any caller): the receiving thread's
// fallback releases only there with the rule off (as before the rule).
std::atomic<uint32_t> g_appear_tid{0};
// How long due releases wait for a thread that may call NotifyAppear (WRN past 2 s).
hold::DeferWatch g_defer;

const hold_test::Seams* g_seams = nullptr;  // tests only
std::string* g_test_lines = nullptr;         // tests only: network_tick's lines

const uint64_t g_qpc_freq = [] {
    LARGE_INTEGER f{};
    QueryPerformanceFrequency(&f);
    return static_cast<uint64_t>(f.QuadPart);
}();

uint64_t qpc_us() {
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return p8p::qpc_to_us(static_cast<uint64_t>(t.QuadPart), g_qpc_freq);
}

void store_max(std::atomic<uint64_t>& mx, uint64_t v) {
    uint64_t cur = mx.load(std::memory_order_relaxed);
    while (v > cur && !mx.compare_exchange_weak(cur, v, std::memory_order_relaxed)) {
    }
}

uint64_t now_ms() { return g_seams && g_seams->now_ms ? g_seams->now_ms() : GetTickCount64(); }

template <class T>
bool peek(uintptr_t a, T& v) {
    return a && game::safe_read(a, &v, sizeof v);
}

// ---------------------------------------------------------------- the log lines (M7)
//
// Every line is a fixed record in a lock-free ring (no formatting, no log
// mutex, no allocation on the game's threads; pushing under g_mu is a few
// stores). child_hold_network_tick formats them on the mod's network thread.

enum NoteKind : uint16_t {
    kNoteNpcTableFull,
    kNoteUnreadableSession,
    kNoteChildForgotten,
    kNoteNpcForgotten,
    kNoteNpcHeld,
    kNoteNpcFullAfterSplit,
    kNoteChildHeld,
    kNoteChildFull,
    kNoteChildUser2Drop,
    kNoteNpcUser2Drop,
    kNoteNpcCtrlChanged,
    kNoteNpcStillHeld,
    kNoteNpcWithheldU2,
    kNoteNpcDropped,
    kNoteNpcReleased,
    kNoteChildTimeout,
    kNoteChildDropped,
    kNoteChildReleased,
    kNoteCharHeld,
    kNoteCharFull,
    kNoteCharFullAfterSplit,
    kNoteCharStill,
    kNoteCharReleased,
    kNoteCharDropped,
    kNoteCharUser2Drop,
    kNoteCharForgotten,
    kNoteNativeThread,
    kNoteSettleHeld,
    kNoteSettleFull,
    kNoteSettleReleased,
    kNoteSettleDropped,
    kNoteSettleUser2Drop,
    kNoteSettleForgotten,
    kNoteSettleD53,
    kNoteLoadDeferred,
    kNoteLoadWould,
    kNoteLoadReleased,
    kNoteLoadPhase,
    kNoteLoadStuck,
    kNoteFamWould,
    kNoteFamHeld,
    kNoteFamReleased,
    kNoteFamDropped,
    kNoteFamOther,
    kNoteFamAc,
    kNoteOutOrphan,
    kNotePubRefused,    // S35 publication_gate: a release refused (retained, or would be with probe)
    kNotePubDropped,    // ... dropped WITHOUT being published (retention over / no room): WRN
    kNotePubNoEntry,    // ... a native exit of a full table: withheld without an entry (or would be)
    kNotePubCcUnknown,  // ... an NPC whose CC could not be read: held instead of announced (or would be)
    kNotePubUnchecked,  // ... a NotifyAppear that went out unchanged without any check (prepare could not run)
    kNoteCount
};

p8p::EventRing<1024> g_notes;
std::atomic<uint64_t> g_notes_lost{0};

uint64_t ptr_bits(const char* s) { return reinterpret_cast<uint64_t>(s); }
const char* bits_ptr(uint64_t v) { return v ? reinterpret_cast<const char*>(v) : ""; }

void note(std::atomic<uint64_t>& counter, uint64_t cap, NoteKind kind, std::initializer_list<uint64_t> v) {
    if (counter.fetch_add(1, std::memory_order_relaxed) >= cap) return;
    p8p::Event e;
    e.kind = kind;
    size_t i = 0;
    for (const uint64_t x : v) {
        if (i < 12) e.v[i++] = x;
    }
    if (!g_notes.push(e)) g_notes_lost.fetch_add(1, std::memory_order_relaxed);
}

void pub_unchecked(uint64_t why, size_t nkeys) {
    if (pub_gate() == pubg::Mode::Off) return;
    (why == 0 ? g_pg_unchecked_sam : why == 1 ? g_pg_unchecked_session : g_pg_unchecked_error)
        .fetch_add(1, std::memory_order_relaxed);
    note(g_pg_unchecked_logged, kMaxPubUncheckedLogged, kNotePubUnchecked, {why, nkeys});
}

// observer_load_defer (review M1): is user 2 inside a load now (2549 .. 2762)? A load that has lasted
// hold::kLoadDeferMaxMs is taken as finished (a stuck phase: a move aborted, a 2762 not seen in take_frame), with
// one warning line per load: nothing more is withheld for it and the passes release what it held.
bool user2_loading_now(uint64_t now) {
    if (!g_user2_loading.load(std::memory_order_relaxed)) return false;
    const uint64_t start = g_load_start_ms.load(std::memory_order_relaxed);
    if (!start || now < start || now - start < hold::kLoadDeferMaxMs) return true;
    if (!g_load_stuck_noted.exchange(true, std::memory_order_relaxed)) {
        g_ld_stuck.fetch_add(1, std::memory_order_relaxed);
        uint64_t end = g_load_end_ms.load(std::memory_order_relaxed);
        const uint64_t capped = start + hold::kLoadDeferMaxMs;
        while (end < capped && !g_load_end_ms.compare_exchange_weak(end, capped, std::memory_order_relaxed)) {
        }
        note(g_ld_phase_logged, kMaxLoadPhaseLogged, kNoteLoadStuck,
             {now - start, g_ld_loads.load(std::memory_order_relaxed), g_npc_size.load(std::memory_order_relaxed)});
    }
    return false;
}

std::string note_text(const p8p::Event& e) {
    const uint64_t* v = e.v;
    auto who = [](uint64_t w) { return owner_who_name(static_cast<OwnerWho>(w)); };
    auto side = [](uint64_t host) { return host ? "host" : "user 2"; };
    switch (e.kind) {
        case kNoteNpcTableFull:
            return std::format("Session2 observer hold: table full ({}): NPC 0x{:08X} (controller 0x{:08X}) is announced "
                               "natively with restore 0",
                               hold::kNpcTableCapacity, v[0], v[1]);
        case kNoteUnreadableSession:
            return std::format("Session2 child hold: recipient session 0x{:X} has no valid user; NotifyAppear runs "
                               "unchanged (with a child of {} at restore 0)",
                               v[0], v[1] ? "the host" : "user 2");
        case kNoteChildForgotten:
            return std::format("Session2 child hold: {} held entr{} announced by the engine itself (restore 1 by then); "
                               "dropped",
                               v[0], v[0] == 1 ? "y" : "ies");
        case kNoteNpcForgotten:
            return std::format("Session2 observer hold: {} held NPC entr{} announced by the engine itself (restore 1 by "
                               "then); dropped",
                               v[0], v[0] == 1 ? "y" : "ies");
        case kNoteNpcHeld:
            return std::format("Session2 observer hold: held NPC 0x{:08X} (type {}, controller {} 0x{:08X}, owner none, "
                               "restore 0) from session 0x{:X} ({} 0x{:08X}); its controller got it now; epoch {}",
                               v[0], v[1], who(v[2]), v[3], v[4], side(v[5]), v[6], v[7]);
        case kNoteNpcFullAfterSplit:
            return std::format("Session2 observer hold: table full ({}) after the split: NPC 0x{:08X} is withheld from "
                               "session 0x{:X} WITHOUT a release entry (should not happen: its room was reserved)",
                               hold::kNpcTableCapacity, v[0], v[1]);
        case kNoteChildHeld:
            return std::format("Session2 child hold: held 0x{:08X} (type {}, owner {} 0x{:08X}, restore 0) from session "
                               "0x{:X} ({} 0x{:08X}); epoch {}",
                               v[0], v[1], who(v[2]), v[3], v[4], side(v[5]), v[6], v[7]);
        case kNoteChildFull:
            return std::format("Session2 child hold: table full ({}): 0x{:08X} is held from session 0x{:X} WITHOUT a "
                               "release entry (it will not appear there)",
                               hold::kTableCapacity, v[0], v[1]);
        case kNoteChildUser2Drop:
            return std::format("Session2 child hold: user 2 is {}; {} held entr{} of it (its children, or children "
                               "withheld from it) dropped (never published); {} left",
                               v[0] ? "leaving (its 2001 was handed)" : "gone", v[1], v[1] == 1 ? "y" : "ies", v[2]);
        case kNoteNpcUser2Drop:
            return std::format("Session2 observer hold: user 2 is {}; {} NPC entr{} withheld from it dropped (never "
                               "published); {} left",
                               v[0] ? "leaving (its 2001 was handed)" : "gone", v[1], v[1] == 1 ? "y" : "ies", v[2]);
        case kNoteNpcCtrlChanged:
            return std::format("Session2 observer hold: NPC 0x{:08X} changed controller 0x{:08X} -> 0x{:08X} while held "
                               "from session 0x{:X}; still waiting for its first action",
                               v[0], v[1], v[2], v[3]);
        case kNoteNpcStillHeld:
            return std::format("Session2 observer hold: NPC 0x{:08X} still held from session 0x{:X} after {} ms ({}); "
                               "released with restore 0 at {} ms if nothing changes",
                               v[0], v[1], v[2], bits_ptr(v[3]), hold::kNpcTimeoutMs);
        case kNoteNpcWithheldU2:
            return std::format("Session2 observer hold: NPC 0x{:08X} withheld from the host (session 0x{:X}): user 2 "
                               "controls it (0x{:08X}), restore 0 for {} ms; never released to the host with restore 0 "
                               "(U-e, the exe+0x1831598 crash): waits for restore 1, the host as its controller or a drop",
                               v[0], v[1], v[2], v[3]);
        case kNoteNpcDropped:
            return std::format("Session2 observer hold: NPC 0x{:08X} (type {}, controller 0x{:08X}) / session 0x{:X} ({}) "
                               "dropped after {} ms: {}",
                               v[0], v[1], v[2], v[3], side(v[4]), v[5], bits_ptr(v[6]));
        case kNoteNpcReleased: {
            const auto kind = static_cast<NpcRelease>(v[7]);
            return std::format("Session2 observer hold: released NPC 0x{:08X} (type {}, controller 0x{:08X}) to session "
                               "0x{:X} ({} 0x{:08X}) after {} ms, {}{}{} ({}; {} key(s) in that 2005)",
                               v[0], v[1], v[2], v[3], side(v[4]), v[5], v[6], npc_release_name(kind),
                               kind == NpcRelease::Native ? ": " : "", kind == NpcRelease::Native ? bits_ptr(v[10]) : "",
                               bits_ptr(v[8]), v[9]);
        }
        case kNoteChildTimeout:
            return std::format("Session2 child hold: CompHold timeout 0x{:08X} (owner {}) from session 0x{:X} ({}): no "
                               "first action after {} ms; still held (never released with restore 0)",
                               v[0], who(v[1]), v[2], side(v[3]), v[4]);
        case kNoteChildDropped:
            return std::format("Session2 child hold: entry 0x{:08X} / session 0x{:X} dropped after {} ms ({})", v[0],
                               v[1], v[2], bits_ptr(v[3]));
        case kNoteChildReleased:
            return std::format("Session2 child hold: released 0x{:08X} (type {}, owner {}) to session 0x{:X} ({} "
                               "0x{:08X}) after {} ms, restore 1 ({})",
                               v[0], v[1], who(v[2]), v[3], side(v[4]), v[5], v[6], bits_ptr(v[7]));
        case kNoteCharHeld:
            return std::format("Session2 character hold: held character 0x{:08X} (type {}, owner {} 0x{:08X}, restore 0) "
                               "from session 0x{:X} ({} 0x{:08X}); its owner got it at once; the others get it after "
                               "its first accepted action, or with restore 0 after {} ms; epoch {}",
                               v[0], v[1], who(v[2]), v[3], v[4], side(v[5]), v[6], hold::kCharTimeoutMs, v[7]);
        case kNoteCharFull:
            return std::format("Session2 character hold: table full ({}): character 0x{:08X} (owner {}) is announced "
                               "natively with restore 0",
                               hold::kCharTableCapacity, v[0], who(v[1]));
        case kNoteCharFullAfterSplit:
            return std::format("Session2 character hold: table full ({}) after the split: character 0x{:08X} is "
                               "withheld from session 0x{:X} WITHOUT a release entry (should not happen: its room was "
                               "reserved)",
                               hold::kCharTableCapacity, v[0], v[1]);
        case kNoteCharStill:
            return std::format("Session2 character hold: CharHold wait 0x{:08X} (owner {}) still held from session "
                               "0x{:X} ({}) after {} ms ({}); announced with restore 0 at {} ms if no action of it is "
                               "accepted",
                               v[0], who(v[1]), v[2], side(v[3]), v[4], bits_ptr(v[5]), hold::kCharTimeoutMs);
        case kNoteCharReleased: {
            const auto kind = static_cast<CharRelease>(v[7]);
            return std::format("Session2 character hold: released character 0x{:08X} (type {}, owner {}) to session "
                               "0x{:X} ({} 0x{:08X}) after {} ms, {} ({}; {})",
                               v[0], v[1], who(v[2]), v[3], side(v[4]), v[5], v[6], char_release_name(kind),
                               bits_ptr(v[9]), bits_ptr(v[8]));
        }
        case kNoteCharDropped:
            return std::format("Session2 character hold: character 0x{:08X} (owner {}) / session 0x{:X} ({}) dropped "
                               "after {} ms: {} (nothing published; the observer does not see it now)",
                               v[0], who(v[1]), v[2], side(v[3]), v[4], bits_ptr(v[5]));
        case kNoteCharUser2Drop:
            return std::format("Session2 character hold: user 2 is {}; {} held character entr{} dropped (never "
                               "published); {} left",
                               v[0] ? "leaving (its 2001 was handed)" : "gone", v[1], v[1] == 1 ? "y" : "ies", v[2]);
        case kNoteCharForgotten:
            return std::format("Session2 character hold: {} held character entr{} announced by the engine itself; "
                               "dropped",
                               v[0], v[0] == 1 ? "y" : "ies");
        case kNoteNativeThread:
            return std::format("Session2 child hold: thread {} calls NotifyAppear natively (from exe+0x{:X}); the "
                               "holds' native re-announcements run only on such threads ({} known)",
                               v[0], v[1], v[2]);
        case kNoteSettleHeld:
            return std::format("Session2 child settle: held 0x{:08X} (type {}, owner {} 0x{:08X}, restore {}) from "
                               "session 0x{:X} ({} 0x{:08X}): its owner's character 0x{:08X} {}; released {} ms after "
                               "that character's announcement there; epoch {}",
                               v[0], v[1], who(v[2]), v[3], v[9] == 0xFF ? std::string("?") : std::to_string(v[9]), v[4],
                               side(v[5]), v[6], v[8], v[10] ? "goes in the same NotifyAppear" : "was announced there just now",
                               v[11], v[7]);
        case kNoteSettleFull:
            return std::format("Session2 child settle: table full ({}): 0x{:08X} (owner {}) is announced natively "
                               "together with its owner's character (as without the key)",
                               hold::kSettleTableCapacity, v[0], who(v[1]));
        case kNoteSettleReleased: {
            const auto kind = static_cast<cst::Kind>(v[7]);
            return std::format("Session2 child settle: released 0x{:08X} (type {}, owner {}) to session 0x{:X} ({} "
                               "0x{:08X}) after {} ms, {} ({}; {})",
                               v[0], v[1], who(v[2]), v[3], side(v[4]), v[5], v[6], cst::kind_name(kind), bits_ptr(v[9]),
                               bits_ptr(v[8]));
        }
        case kNoteSettleDropped:
            return std::format("Session2 child settle: 0x{:08X} (owner {}) / session 0x{:X} ({}) dropped after {} ms: {} "
                               "(nothing published; the observer does not see it now)",
                               v[0], who(v[1]), v[2], side(v[3]), v[4], bits_ptr(v[5]));
        case kNoteSettleUser2Drop:
            return std::format("Session2 child settle: user 2 is {}; {} held entr{} dropped (never published); {} left",
                               v[0] ? "leaving (its 2001 was handed)" : "gone", v[1], v[1] == 1 ? "y" : "ies", v[2]);
        case kNoteSettleForgotten:
            return std::format("Session2 child settle: {} held entr{} announced by the engine itself; dropped", v[0],
                               v[0] == 1 ? "y" : "ies");
        case kNoteSettleD53:
            return std::format("Session2 child settle: D-53's release of 0x{:08X} to session 0x{:X} waits: its owner's "
                               "character 0x{:08X} {}",
                               v[0], v[1], v[2], v[3] ? "is still withheld there" : "was announced there less than "
                                                                                    "child_settle_ms ago");
        case kNoteLoadDeferred:
            return std::format("Session2 observer load defer: NPC 0x{:08X} (type {}, controller 0x{:08X}, restore 1) "
                               "withheld from session 0x{:X} (user 2 0x{:08X}): user 2 is loading; announced natively "
                               "after its 2762 (at most {} ms); epoch {}",
                               v[0], v[1], v[2], v[3], v[4], hold::kLoadDeferMaxMs, v[5]);
        case kNoteLoadWould:
            return std::format("Session2 observer load defer (probe): NPC 0x{:08X} (type {}, controller 0x{:08X}, "
                               "restore 1) goes to session 0x{:X} (user 2 0x{:08X}) while user 2 is loading: WOULD be "
                               "withheld until its 2762",
                               v[0], v[1], v[2], v[3], v[4]);
        case kNoteLoadReleased:
            return std::format("Session2 observer load defer: released NPC 0x{:08X} (type {}) to session 0x{:X} after "
                               "{} ms, {} ({}; {} key(s) in that NotifyAppear)",
                               v[0], v[1], v[2], v[3],
                               v[4] ? "AT THE CAP: user 2 still loading, announced as the engine would" :
                                      "user 2's 2762 written",
                               bits_ptr(v[5]), v[6]);
        case kNoteLoadPhase:
            return std::format("Session2 observer load defer: user 2 {} (load #{}); NPCs withheld now {}",
                               v[0] ? "starts a login / field load: NPCs announced to it wait for its 2762" :
                                      "has its 2762: the withheld NPCs are announced by the next passes",
                               v[1], v[2]);
        case kNoteLoadStuck:
            return std::format("Session2 observer load defer: user 2's load #{} has lasted {} ms without its 2762 (a "
                               "stuck move phase?): taken as finished; nothing more is withheld for it and the withheld "
                               "NPCs ({} entries now) are released by the usual rules",
                               v[1], v[0], v[2]);
        case kNoteFamWould:
            return std::format("Session2 observer hold family (probe): member 0x{:08X} (type {}, parent 0x{:08X}) goes "
                               "to session 0x{:X} although {}: WOULD be withheld and announced right behind its parent",
                               v[0], v[1], v[2], v[3], family_why_name(static_cast<FamilyWhy>(v[4])));
        case kNoteFamHeld:
            return std::format("Session2 observer hold family: held member 0x{:08X} (type {}, parent 0x{:08X}; {} gets "
                               "it now) from session 0x{:X} ({} 0x{:08X}): {}; announced right behind its parent; epoch "
                               "{}",
                               v[0], v[1], v[2], who(v[7]), v[3], side(v[4]), v[5],
                               family_why_name(static_cast<FamilyWhy>(v[8])), v[6]);
        case kNoteFamReleased: {
            const auto kind = static_cast<FamilyRelease>(v[6]);
            return std::format("Session2 observer hold family: released member 0x{:08X} (type {}, parent 0x{:08X}, "
                               "depth {}) to session 0x{:X} ({}) after {} ms, {} ({}; {} key(s) in that 2005)",
                               v[0], v[1], v[2], v[9], v[3], side(v[4]), v[5], family_release_name(kind),
                               bits_ptr(v[7]), v[8]);
        }
        case kNoteFamDropped:
            return std::format("Session2 observer hold family: member 0x{:08X} (parent 0x{:08X}) / session 0x{:X} ({}) "
                               "dropped after {} ms: {} (nothing published)",
                               v[0], v[1], v[2], side(v[3]), v[4], bits_ptr(v[5]));
        case kNoteFamOther:
            switch (v[0]) {
                case 0:
                    return std::format("Session2 observer hold family: table full ({}): member 0x{:08X} (parent "
                                       "0x{:08X}) is announced natively (before its parent, as without the key)",
                                       hold::kFamilyTableCapacity, v[1], v[2]);
                case 1:
                    return std::format("Session2 observer hold family: table full ({}) after the split: member "
                                       "0x{:08X} is withheld from session 0x{:X} WITHOUT an entry (should not happen: "
                                       "its room was reserved)",
                                       hold::kFamilyTableCapacity, v[1], v[2]);
                case 2:
                    return std::format("Session2 observer hold family: member 0x{:08X} (parent 0x{:08X}) left native: "
                                       "its recipients cannot be split (one user would get it now on one session and "
                                       "not on another, or both users must wait) (partial)",
                                       v[1], v[2]);
                case 3:
                    return std::format("Session2 observer hold family: 0x{:08X} (type {}) has an unreadable hierarchy "
                                       "component (or another actor's): left native (unlinked)",
                                       v[1], v[2]);
                case 4:
                    return std::format("Session2 observer hold family: user 2 is {}; {} member entr{} withheld from it "
                                       "dropped (never published); {} left",
                                       v[1] ? "leaving (its 2001 was handed)" : "gone", v[2], v[2] == 1 ? "y" : "ies",
                                       v[3]);
                case 5:
                    return std::format("Session2 observer hold family: {} member entr{} announced by the engine itself; "
                                       "dropped",
                                       v[1], v[1] == 1 ? "y" : "ies");
                case 6:
                    return std::format("Session2 observer hold family: member 0x{:08X} (parent 0x{:08X}) despawned "
                                       "before its release to session 0x{:X}; dropped",
                                       v[1], v[2], v[3]);
                case 7:
                    return std::format("Session2 observer hold family: NPC 0x{:08X} was due to session 0x{:X} before its "
                                       "parent 0x{:08X} reached it: it waits for its parent now (a family entry)",
                                       v[1], v[3], v[2]);
                case 8:
                    return std::format("Session2 observer hold family: NPC 0x{:08X} was due before its parent 0x{:08X} "
                                       "reached user 2, but the family table is full ({}): released now (an orphan, as "
                                       "without the key)",
                                       v[1], v[2], hold::kFamilyTableCapacity);
                case 9:
                    return std::format("Session2 observer hold family: user 2's announced-keys set is full ({} keys): "
                                       "every parent counts as announced until its next epoch (as without the key)",
                                       v[1]);
                case 10:
                    return std::format("Session2 observer hold family (probe): NPC 0x{:08X} released to session 0x{:X} "
                                       "before its parent 0x{:08X} reached it: WOULD wait for it",
                                       v[1], v[3], v[2]);
                case 11:
                    return std::format("Session2 observer hold family: {} members waited in vain for a parent user 2 "
                                       "never got (of {} that waited for one): the hierarchy may name parents the "
                                       "engine does not send; the \"not announced yet\" rule is OFF for the rest of "
                                       "the process (a parent WITHHELD from user 2 still keeps its family behind it)",
                                       v[1], v[2]);
                default: break;
            }
            return std::format("Session2 observer hold family: note {}?", v[0]);
        case kNoteFamAc:
            return std::format("Session2 observer hold family [probe of the source]: 0x{:08X} (type {}): hierarchy "
                               "parent 0x{:08X}, the server actor's +0x{:X} 0x{:08X} ({})",
                               v[0], v[3], v[1], hold::kActorParent, v[2],
                               v[1] == v[2] ? "same" : v[1] ? "DIFFERENT" : "only +0xAC names one");
        case kNoteOutOrphan:
            return std::format("Session2 family order: ORPHAN queued for user 2: record 0x{:08X} (type {}) names "
                               "parent 0x{:08X}, which user 2 has not been given (no earlier 2005 since its last 2516, "
                               "not in this 2005: {} record(s), {} orphan(s)); its client destroys it (0x8B7D78)",
                               v[0], v[1], v[2], v[3], v[4]);
        case kNotePubRefused:
            return std::format("Session2 publication gate: {} 0x{:08X} (type {}) to {}'s session 0x{:X}: {} (parent "
                               "0x{:08X}; release '{}', held {} ms; CC slot 0x{:X})",
                               v[6] ? "WOULD RETAIN (probe, published as before)" : "RETAINED, not published", v[0],
                               v[1], side(v[3]), v[2], pubg::verdict_name(static_cast<pubg::Verdict>(v[4])), v[5],
                               bits_ptr(v[7]), v[8], v[9]);
        case kNotePubDropped:
            return std::format("Session2 publication gate: DROPPED WITHOUT PUBLISHING 0x{:08X} (type {}) for {}'s "
                               "session 0x{:X}: {} for {} ms ({}); invisible to that observer until the engine "
                               "announces it again",
                               v[0], v[1], side(v[3]), v[2], pubg::verdict_name(static_cast<pubg::Verdict>(v[4])), v[5],
                               v[6] ? "its table had no room to keep it" : "publication_retain_max_ms reached");
        case kNotePubNoEntry:
            return std::format("Session2 publication gate: {} table full: 0x{:08X} (type {}, controller 0x{:08X}) {}",
                               v[3] ? "family" : "observer hold", v[0], v[1], v[2],
                               v[4] ? "WOULD be withheld without an entry (probe: announced natively as before)"
                                    : "withheld WITHOUT an entry instead of announced natively (invisible to that "
                                      "observer until the engine announces it again)");
        case kNotePubCcUnknown:
            return std::format("Session2 publication gate: NPC 0x{:08X} (type {}, controller 0x{:08X}): its CC could not "
                               "be read (slot 0x{:X}; not proven absent): {}",
                               v[0], v[1], v[2], v[3],
                               v[4] ? "WOULD be held (probe: announced natively as before)"
                                    : "held like a restore-0 NPC, never announced to a non-controller");
        case kNotePubUnchecked:
            return std::format("Session2 publication gate: a NotifyAppear of {} key(s) went out UNCHECKED ({}): the "
                               "gate could not evaluate it (restore 0 may have reached a non-controller)",
                               v[1], v[0] == 0 ? "actor manager unreadable" : v[0] == 1 ? "a recipient session unreadable"
                                                                                    : "an error in the split");
        default:
            return std::format("Session2 child hold: note {}?", e.kind);
    }
}

// Lines logged as warnings: a character announced with restore 0 (timeout, table full) or natively.
bool note_warns(const p8p::Event& e) {
    if (e.kind == kNoteCharFull || e.kind == kNoteCharFullAfterSplit || e.kind == kNoteSettleFull) return true;
    if (e.kind == kNoteLoadStuck) return true;
    if (e.kind == kNoteFamOther) return e.v[0] == 1 || e.v[0] == 8 || e.v[0] == 9 || e.v[0] == 11;
    if (e.kind == kNoteFamReleased) {
        const auto kind = static_cast<FamilyRelease>(e.v[6]);
        return kind == FamilyRelease::MaxAge || kind == FamilyRelease::OrphanTimeout;
    }
    if (e.kind == kNoteOutOrphan) return true;
    if (e.kind == kNotePubDropped || e.kind == kNotePubUnchecked) return true;
    if (e.kind == kNoteSettleReleased) {
        const auto kind = static_cast<cst::Kind>(e.v[7]);
        return kind == cst::Kind::MaxWait || kind == cst::Kind::Native;
    }
    if (e.kind != kNoteCharReleased) return false;
    const auto kind = static_cast<CharRelease>(e.v[7]);
    return kind == CharRelease::Timeout || kind == CharRelease::Native;
}

// The mod's network thread only: one line to the log (or to the tests' buffer).
void out_line(bool warn, const std::string& line) {
    if (g_test_lines) {
        *g_test_lines += warn ? "WRN " : "";
        *g_test_lines += line;
        *g_test_lines += '\n';
    } else if (warn) {
        log::warn("{}", line);
    } else {
        log::info("{}", line);
    }
}

// The mod's network thread only.
void drain_notes() {
    p8p::Event e;
    while (g_notes.pop(e)) {
        std::string line = note_text(e);
        if (g_test_lines) {
            *g_test_lines += note_warns(e) ? "WRN " : "";
            *g_test_lines += line;
            *g_test_lines += '\n';
        } else if (note_warns(e)) {
            log::warn("{}", line);
        } else {
            log::info("{}", line);
        }
    }
    static uint64_t lost_logged = 0;
    const uint64_t lost = g_notes_lost.load(std::memory_order_relaxed);
    if (lost != lost_logged && !g_test_lines) {
        log::warn("Session2 child hold: {} log line(s) lost (ring full)", lost - lost_logged);
        lost_logged = lost;
    }
}

// ---------------------------------------------------------------- reads of the game's state

// The current thread runs in the server's realm (as NotifyAppear and the
// restore write require): the game's own TLS byte, read only (the thread's own
// TLS block: SEH reads are enough).
bool server_realm() {
    if (g_seams) return g_seams->realm;
    if (!g_profile) return false;
    const uintptr_t tls_array = static_cast<uintptr_t>(__readgsqword(0x58));
    const auto block = game::fast<uintptr_t>(tls_array);
    const auto flag = block && *block ? game::fast<uint8_t>(*block + g_profile->tls_realm) : std::nullopt;
    return flag && *flag != 0;
}

uint32_t cur_tid() { return g_seams && g_seams->thread_id ? g_seams->thread_id() : GetCurrentThreadId(); }

// The current thread is one the game itself used for NotifyAppear (seen in
// notify_detour from a native call site): the only threads where the holds call
// NotifyAppear. The slots fill left to right, so an empty one ends the search.
bool native_appear_thread() {
    const uint32_t t = cur_tid();
    for (const auto& s : g_native_tids) {
        const uint32_t v = s.load(std::memory_order_acquire);
        if (v == t) return true;
        if (!v) return false;
    }
    return false;
}

// May this thread call NotifyAppear for a release now? With notify_thread_rule=1
// only a native NotifyAppear thread; with 0 (default) as before the rule: the
// StartActionReq handler's own thread (on_handler_thread), else only the last
// thread that called NotifyAppear. The server realm is checked by the callers.
bool may_notify_here(bool on_handler_thread) {
    if (g_thread_rule.load(std::memory_order_relaxed)) return native_appear_thread();
    return on_handler_thread || cur_tid() == g_appear_tid.load(std::memory_order_relaxed);
}

// notify_detour's entry: its caller's return address is one of NotifyAppear's
// two native call sites (0x2AF90EB / 0x2AF92D1 + 5; companeros-publicacion.md
// §1.2) -> this thread calls it natively. Anything else is counted (the mod
// calls it only through the trampoline, which this detour never sees).
void note_native_caller(uintptr_t ret) {
    uintptr_t site = 0;
    if (g_seams) {
        site = 1;  // the tests' notify() stands for the engine's own call
    } else if (g_profile && ret == g_base + g_profile->caller_new + 5) {
        site = g_profile->caller_new;
    } else if (g_profile && ret == g_base + g_profile->caller_moving + 5) {
        site = g_profile->caller_moving;
    }
    if (!site) {
        g_notify_foreign.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    const uint32_t t = cur_tid();
    for (auto& s : g_native_tids) {
        uint32_t v = s.load(std::memory_order_acquire);
        if (v == t) return;
        if (v == 0) {
            if (s.compare_exchange_strong(v, t, std::memory_order_acq_rel)) {
                const uint64_t n = g_native_count.fetch_add(1) + 1;
                note(g_native_logged, hold::kNativeThreads, kNoteNativeThread, {t, site, n});
                return;
            }
            if (v == t) return;
        }
    }
    g_native_full.fetch_add(1, std::memory_order_relaxed);
}

// The ServerActorManager (fast: observer_hold's reads).
std::optional<uintptr_t> sam_now(bool fast) {
    if (g_seams) return g_seams->sam ? std::optional<uintptr_t>(g_seams->sam) : std::nullopt;
    return profile::sam_ptr(g_base, [fast](uintptr_t a) { return fast ? game::fast_ptr(a) : read_ptr(a); });
}

uintptr_t user_vtable_now() {
    // The fake-memory tests deliberately retain their legacy vtable sentinel.
    if (g_seams) return g_seams->base + off::kServerUserActorVtable;
    const uintptr_t vt = profile::rva(off::kServerUserActorVtable);
    return vt ? g_base + vt : 0;
}

// The host's user now (0 = unreadable) and its key (the last one read if unreadable now).
uint32_t host_key_now(uintptr_t& host) {
    host = 0;
    uint32_t key = 0;
    if (!server_host_user(host)) host = 0;
    if (host && peek(host + hold::kUserKey, key) && key) {
        g_host_key.store(key);
        return key;
    }
    return g_host_key.load();
}

uint32_t user_key_of(uintptr_t user) {
    uint32_t k = 0;
    return peek(user + hold::kUserKey, k) ? k : 0;
}

uint32_t user_key_fast(uintptr_t user) { return game::fast<uint32_t>(user + hold::kUserKey).value_or(0); }

bool retired_for_publication(uint32_t key);

void call_notify(uintptr_t flag, const GameVec* sessions, const GameVec* keys) {
    child_hold_settle_births();  // S33 review: a retired key born again, before any retired-key filter
    NpcPublicationScope in_flight;
    auto publication = observer_hold_acks_publication_guard();
    // Una liberación puede haber decidido sobre un snapshot antes del retiro.
    // Revalidar justo antes de la llamada nativa, también para el anfitrión.
    GameVec filtered{};
    std::array<uint32_t, kMaxKeys> live;
    size_t live_count = 0;
    if (publication.owns_lock()) {
        GameVec input{};
        if (peek(reinterpret_cast<uintptr_t>(keys), input) && input.count <= kMaxKeys) {
            bool valid = true;
            for (uint32_t i = 0; i < input.count; ++i) {
                uint32_t key = 0;
                if (!peek(reinterpret_cast<uintptr_t>(input.data) + sizeof(uint32_t) * i, key)) { valid = false; break; }
                if (!retired_for_publication(key)) live[live_count++] = key;
            }
            if (valid && live_count != input.count) {
                if (!live_count) return;
                filtered = {live.data(), static_cast<uint32_t>(live_count), static_cast<uint32_t>(live_count)};
                keys = &filtered;
            }
        }
    }
    if (publication.owns_lock()) publication.unlock(); // nunca mantenerlo dentro de NotifyAppear nativo
    if (g_seams && g_seams->notify) {
        g_seams->notify(flag, sessions, keys);
        return;
    }
    g_notify.unsafe_call<void>(flag, sessions, keys);
}

// What one call carries, read from the engine's structs (copies: the engine
// keeps its memory, we keep ours).
struct CallView {
    GameVec sv{}, kv{};
    std::vector<uintptr_t> sessions;
    std::vector<uint32_t> keys;
    bool read = false;
};

bool read_call(const GameVec* sessions, const GameVec* keys, CallView& c) {
    if (!peek(reinterpret_cast<uintptr_t>(sessions), c.sv) || !peek(reinterpret_cast<uintptr_t>(keys), c.kv)) return false;
    if (!c.sv.count || !c.kv.count || c.sv.count > kMaxSessions || c.kv.count > kMaxKeys || !c.sv.data ||
        !c.kv.data) {
        return false;
    }
    c.sessions.resize(c.sv.count);
    c.keys.resize(c.kv.count);
    c.read = game::safe_read(reinterpret_cast<uintptr_t>(c.sv.data), c.sessions.data(),
                             c.sessions.size() * sizeof(uintptr_t)) &&
             game::safe_read(reinterpret_cast<uintptr_t>(c.kv.data), c.keys.data(), c.keys.size() * sizeof(uint32_t));
    return c.read;
}

// The NPC table room a split promised (I2): taken under g_mu in prepare(),
// given back under g_mu when the split is recorded or abandoned. Invariant:
// size + reserved <= capacity, so an NPC is never withheld without its entry.
// The same for the character table (chars).
struct NpcReservation {
    size_t n = 0;
    size_t chars = 0;
    size_t settle = 0;  // child_settle's table
    size_t pieces = 0;  // observer_hold_family's table
    void give_back() {
        if (!n && !chars && !settle && !pieces) return;
        std::lock_guard lock(g_mu);
        g_npc_reserved -= std::min(n, g_npc_reserved);
        g_char_reserved -= std::min(chars, g_char_reserved);
        g_settle_reserved -= std::min(settle, g_settle_reserved);
        g_fam_reserved -= std::min(pieces, g_fam_reserved);
        n = 0;
        chars = 0;
        settle = 0;
        pieces = 0;
    }
    ~NpcReservation() { give_back(); }
};

// ---------------------------------------------------------------- observer_hold_family: what user 2 has

// Under g_mu: user 2's announced set belongs to its live session 2 and guest epoch; another one empties it.
void known_sync_locked(uintptr_t s2, uint32_t epoch) {
    if (g_known_session == s2 && g_known_epoch == epoch) return;
    g_known.clear();
    g_known_session = s2;
    g_known_epoch = epoch;
}

// Under g_mu: these keys were announced to user 2's session (an overflow is told once).
void known_add_locked(std::span<const uint32_t> keys) {
    if (!g_known_session) return;
    const bool was = g_known.overflow();
    for (const uint32_t k : keys) if (!observer_hold_acks_retired(k)) (void)g_known.insert(k);
    if (!was && g_known.overflow()) {
        g_fm_known_overflow.fetch_add(1, std::memory_order_relaxed);
        note(g_fm_other_logged, kMaxFamOtherLogged, kNoteFamOther, {9, hold::kFamilyKnownSlots * 3 / 4});
    }
}

// The withheld (key, observer) pairs of every table (observer_hold, family, D-53 child, child_settle) towards
// the recipients of one call, sorted: one copy per split, then binary searches (review 5). defer: an entry of
// it is observer_load_defer's.
struct WithheldKey {
    uint32_t key = 0;
    uintptr_t observer = 0;
    bool defer = false;
    bool operator<(const WithheldKey& o) const { return key != o.key ? key < o.key : observer < o.observer; }
};

// Under g_mu.
void withheld_index_locked(std::span<const uintptr_t> sessions, std::vector<WithheldKey>& out) {
    out.clear();
    auto add = [&](const auto& t) {
        for (size_t i = 0; i < t.size(); ++i) {
            const HoldEntry& e = t.at(i);
            if (std::find(sessions.begin(), sessions.end(), e.observer) != sessions.end()) {
                out.push_back({e.key, e.observer, e.defer});
            }
        }
    };
    add(g_npc_table);
    add(g_fam_table);
    add(g_table);
    add(g_settle_table);
    std::sort(out.begin(), out.end());
}

bool withheld_in(const std::vector<WithheldKey>& idx, uint32_t key, uintptr_t session, bool* defer) {
    WithheldKey probe;
    probe.key = key;
    probe.observer = session;
    auto it = std::lower_bound(idx.begin(), idx.end(), probe);
    bool found = false;
    for (; it != idx.end() && it->key == key && it->observer == session; ++it) {
        found = true;
        if (defer && it->defer) *defer = true;
    }
    return found;
}

// The server actor's own +0xAC against its hierarchy's parent (counted, a few lines).
template <class M>
void family_ac_probe(const M& m, uint32_t key, uintptr_t actor, uint32_t hier_parent, uint8_t type) {
    const auto ac = m.template rd<uint32_t>(actor + hold::kActorParent);
    if (!ac) return;
    const bool plausible = (*ac >> 28) == hold::kChildKeyClass && *ac != key;
    if (hier_parent && *ac == hier_parent) {
        g_fm_ac_same.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (!hier_parent && !plausible) return;  // neither names a parent
    (hier_parent ? g_fm_ac_other : g_fm_ac_only).fetch_add(1, std::memory_order_relaxed);
    note(g_fm_ac_logged, kMaxFamAcLogged, kNoteFamAc, {key, hier_parent, *ac, type});
}

// observer_hold_family: the parent a server actor's 2005 record names (hold::kActorParent, the u32 +0xAC the
// serializer writes; an 0xB key other than its own), else its hierarchy's (`hier`, piece_parent_with). 0: none;
// nullopt: neither can be read (unlinked).
template <class M>
std::optional<uint32_t> family_parent_with(const M& m, uintptr_t actor, uint32_t key,
                                           const std::optional<uint32_t>& hier) {
    const auto ac = m.template rd<uint32_t>(actor + hold::kActorParent);
    if (ac && (*ac >> 28) == hold::kChildKeyClass && *ac != key) return *ac;
    if (hier && *hier) return *hier;
    if (ac || hier) return uint32_t{0};
    return std::nullopt;
}

// S33: un hijo creado después de la retirada también pertenece a la unidad
// cancelada. Se observa la relación nativa antes de publicarlo; el tracker lo
// retirará en su siguiente punto seguro. No se adivina el padre por el paquete.
bool retired_for_publication(uint32_t key) {
    if (observer_hold_acks_retired(key)) return true;
    if ((key >> 28) != hold::kChildKeyClass) return false;
    const auto sam = sam_now(true);
    const game::FastReads m;
    const auto actor = sam ? find_actor_with(m, *sam, key) : std::nullopt;
    if (!actor || !*actor) return false;
    const auto parent = family_parent_with(m, *actor, key, piece_parent_with(m, *actor));
    if (!parent || !*parent || !observer_hold_acks_retired(*parent)) return false;
    // Su controlador observado: la retirada local lo revalida antes de su Logout.
    user2_stages_npc_late_family(key, *parent, m.rd<uint32_t>(*actor + hold::kActorController).value_or(0));
    const uint64_t generation = user2_stages_npc_birth_token(key);
    // Revisión: estamos dentro de esta misma publicación (su NpcPublicationScope): sólo las de OTROS hilos
    // impiden escribir la lápida.
    if (generation) {
        (void)child_hold_retire_family(server_epoch(), generation, std::span<const uint32_t>(&key, 1),
                                       /*from_publication=*/true);
    }
    return true;
}

// observer_hold_family (pendientes/p8-s14-viajeros.md §7): every 0xB key of this call that no other rule
// withholds and whose record names a parent P (family_parent_with: +0xAC, else the hierarchy) is withheld from a
// recipient session when P is withheld there in this call (it then follows P exactly: same owner, same group,
// the call's order), P has an entry withheld
// there, or that session is user 2's and P has not been announced to it. A member of a member waits for the
// first decision (a few rounds; deeper or circular chains stay native). The receiving user is fam::family_owner
// (mixed -> native, partial). Mode 2 withholds it (room reserved here under the lock, as observer_hold's; full
// -> native), mode 1 only counts. Unreadable hierarchy (unlinked) -> native.
void prepare_family(const CallView& c, std::span<const uintptr_t> users, uintptr_t host, uintptr_t user2,
                    std::vector<HoldVerdict>& verdicts, NpcReservation& reservation, uint8_t mode) {
    struct Cand {
        size_t j = 0;
        uint32_t parent = 0;
        size_t pj = SIZE_MAX;  // the parent's index in this call (SIZE_MAX: not in it)
        bool done = false;
    };
    // User 2's session among the recipients (its announced set applies there only).
    const uintptr_t live = server_live_session2();
    uintptr_t s2 = 0;
    for (size_t i = 0; i < c.sessions.size() && live && user2; ++i) {
        if (c.sessions[i] == live && users[i] == user2) s2 = live;
    }
    // Review 5: nothing can be withheld behind a parent when user 2 is not a recipient, nothing is withheld in this
    // call and every table is empty (e.g. the host's own calls with nothing held): no reads at all.
    if (!s2 && std::none_of(verdicts.begin(), verdicts.end(), [](const HoldVerdict& v) { return v.hold; }) &&
        !g_npc_size.load(std::memory_order_relaxed) && !g_fam_size.load(std::memory_order_relaxed) &&
        !g_size.load(std::memory_order_relaxed) && !g_settle_size.load(std::memory_order_relaxed)) {
        return;
    }
    // The call's keys, sorted, to find a parent in it.
    std::vector<std::pair<uint32_t, uint32_t>> in_call(c.keys.size());
    for (size_t j = 0; j < c.keys.size(); ++j) in_call[j] = {c.keys[j], static_cast<uint32_t>(j)};
    std::sort(in_call.begin(), in_call.end());
    std::vector<Cand> cands;
    std::vector<int> cand_of(c.keys.size(), -1);
    const game::FastReads m;
    for (size_t j = 0; j < c.keys.size(); ++j) {
        const HoldVerdict& v = verdicts[j];
        const uint32_t key = c.keys[j];
        // S33 review: with both S33 keys at 0 a withheld key is skipped before any read, as in c7ae132.
        if ((key >> 28) != hold::kChildKeyClass || !v.actor ||
            (v.hold && !g_npc_family_observe.load(std::memory_order_relaxed))) continue;
        const auto hier = piece_parent_with(m, v.actor);
        family_ac_probe(m, key, v.actor, hier.value_or(0), v.type);
        const auto parent = family_parent_with(m, v.actor, key, hier);
        if (!parent) {
            g_fm_unlinked.fetch_add(1, std::memory_order_relaxed);
            note(g_fm_other_logged, kMaxFamOtherLogged, kNoteFamOther, {3, key, v.type});
            continue;
        }
        user2_stages_npc_family_observed(key, *parent, v.controller, v.type);
        if (v.hold || !*parent || *parent == key) continue;
        Cand cd;
        cd.j = j;
        cd.parent = *parent;
        const auto it = std::lower_bound(in_call.begin(), in_call.end(), std::pair<uint32_t, uint32_t>{*parent, 0});
        if (it != in_call.end() && it->first == *parent) cd.pj = it->second;
        cand_of[j] = static_cast<int>(cands.size());
        cands.push_back(cd);
    }
    if (cands.empty()) return;
    g_fm_seen.fetch_add(cands.size(), std::memory_order_relaxed);
    const uint32_t epoch = server_epoch();
    std::vector<WithheldKey> withheld;
    withheld.reserve(64);
    std::lock_guard lock(g_mu);
    known_sync_locked(live, epoch);
    withheld_index_locked(c.sessions, withheld);
    const size_t free = g_fam_table.room() - std::min(g_fam_table.room(), g_fam_reserved);
    size_t used = 0;
    auto decide = [&](const Cand& cd) {
        HoldVerdict& v = verdicts[cd.j];
        const uint32_t key = c.keys[cd.j];
        uintptr_t owner = 0;
        OwnerWho who = OwnerWho::None;
        bool defer = false;
        FamilyWhy why = FamilyWhy::ParentHeld;
        uintptr_t first_need = 0;
        if (cd.pj != SIZE_MAX) {
            // Its parent in this very call: withheld from some recipient -> the member follows it exactly (its
            // owner's sessions get both in one group, in the call's order); else both go in the pass's 2005.
            const HoldVerdict& pv = verdicts[cd.pj];
            if (!pv.hold || !pv.owner) return;
            owner = pv.owner;
            who = pv.owner_who;
            defer = pv.defer;
            why = FamilyWhy::ParentInCall;
            for (size_t i = 0; i < c.sessions.size() && !first_need; ++i) {
                if (c.sessions[i] && users[i] != owner) first_need = c.sessions[i];
            }
            if (!first_need) return;  // only its parent's receiver gets it now: nothing to withhold
        } else {
            std::array<bool, kMaxSessions> need{};
            bool any = false, unknown = false;
            for (size_t i = 0; i < c.sessions.size(); ++i) {
                if (!c.sessions[i]) continue;
                if (withheld_in(withheld, cd.parent, c.sessions[i], &defer)) {
                    need[i] = true;
                } else if (c.sessions[i] == s2 && !g_fm_unknown_off.load(std::memory_order_relaxed) &&
                           !g_known.contains(cd.parent)) {
                    need[i] = true;
                    unknown = true;
                }
                if (need[i] && !first_need) first_need = c.sessions[i];
                any = any || need[i];
            }
            if (!any) return;
            why = unknown ? FamilyWhy::ParentUnknown : FamilyWhy::ParentHeld;
            owner = fam::family_owner(c.sessions, users, std::span<const bool>(need.data(), c.sessions.size()), host,
                                      user2);
            if (!owner) {
                g_fm_partial.fetch_add(1, std::memory_order_relaxed);
                note(g_fm_other_logged, kMaxFamOtherLogged, kNoteFamOther, {2, key, cd.parent});
                return;
            }
            who = owner == host ? OwnerWho::Host : OwnerWho::Guest;
        }
        size_t n_obs = 0;
        for (size_t i = 0; i < c.sessions.size(); ++i) n_obs += c.sessions[i] && users[i] != owner ? 1 : 0;
        if (mode < 2) {
            g_fm_would.fetch_add(1, std::memory_order_relaxed);
            note(g_fm_logged, kMaxFamLogged, kNoteFamWould,
                 {key, v.type, cd.parent, first_need, static_cast<uint64_t>(why)});
            return;
        }
        bool no_entry = false;
        if (used + n_obs > free) {
            g_fm_full.fetch_add(1, std::memory_order_relaxed);
            // S35 publication_gate=1: behind a withheld / unknown parent, a full table withholds it WITHOUT an entry
            // instead of announcing it natively before its parent. probe: counted, announced as before.
            const pubg::Mode gate = pub_gate();
            const bool withhold = pubg::withhold_without_entry(gate);
            if (gate != pubg::Mode::Off) {
                (withhold ? g_pg_withheld_no_entry : g_pg_would_no_entry).fetch_add(1, std::memory_order_relaxed);
                note(g_pg_entry_logged, kMaxPubEntryLogged, kNotePubNoEntry,
                     {key, v.type, v.controller, 1, static_cast<uint64_t>(!withhold)});
            }
            if (!withhold) {
                note(g_fm_other_logged, kMaxFamOtherLogged, kNoteFamOther, {0, key, cd.parent});
                return;
            }
            no_entry = true;
        } else {
            used += n_obs;
        }
        v.no_entry = no_entry;
        v.hold = true;
        v.family = true;
        v.parent = cd.parent;
        v.family_why = static_cast<uint8_t>(why);
        v.owner = owner;
        v.owner_who = who;
        v.defer = defer;
        v.why = HoldWhy::Hold;
    };
    // A member whose parent is a member in this call too is decided after it.
    for (int round = 0; round < 8; ++round) {
        bool pending = false, progress = false;
        for (Cand& cd : cands) {
            if (cd.done) continue;
            if (cd.pj != SIZE_MAX && cand_of[cd.pj] >= 0 && !cands[static_cast<size_t>(cand_of[cd.pj])].done) {
                pending = true;
                continue;
            }
            cd.done = true;
            progress = true;
            decide(cd);
        }
        if (!pending || !progress) break;
    }
    g_fam_reserved += used;
    reservation.pieces += used;
}

// The split of this call, or false (the original unchanged).
bool prepare(const CallView& c, SplitPlan& plan, NpcReservation& reservation) {
    if (!server_realm()) {
        g_not_realm.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    uintptr_t user2 = 0;
    if (!server_user2(user2)) user2 = 0;
    uintptr_t host = 0;
    const uint32_t host_key = host_key_now(host);
    if (!user2 && !host_key) return false;  // no guest can be in yet
    const bool characters = g_characters.load(std::memory_order_relaxed);
    // Cheap first: only child-class keys (and, with character_hold, characters) are looked up.
    if (std::none_of(c.keys.begin(), c.keys.end(), [&](uint32_t k) {
            return (k >> 28) == hold::kChildKeyClass || (characters && (k >> 28) == hold::kCharKeyClass);
        })) {
        return false;
    }
    // Who each recipient is (a few reads per session). Since the hold covers
    // the host's children too, a list only user 2 receives (it entering the
    // host's sectors) is split as well: the host's new horse is withheld there.
    std::vector<uintptr_t> users(c.sessions.size(), 0);
    uintptr_t unreadable_session = 0;
    for (size_t i = 0; i < c.sessions.size(); ++i) {
        if (!c.sessions[i]) continue;
        if (!server_session_user(c.sessions[i], users[i])) {
            unreadable_session = c.sessions[i];
            users[i] = 0;
        }
    }
    const bool observers = g_observers.load(std::memory_order_relaxed);
    const bool children = g_children.load(std::memory_order_relaxed);
    const auto sam = sam_now(observers);
    if (!sam) {
        pub_unchecked(0, c.keys.size());  // S35 review 11: unchanged, so unchecked
        return false;
    }
    const uintptr_t user_vt = user_vtable_now();
    std::vector<HoldVerdict> verdicts(c.keys.size());
    ObserverHoldUsers ou;
    // observer_load_defer: only when user 2 is a recipient of this call.
    uintptr_t user2_session = 0;
    for (size_t i = 0; i < c.sessions.size() && user2; ++i) {
        if (c.sessions[i] && users[i] == user2) user2_session = c.sessions[i];
    }
    if (observers) {
        ou.host = host;
        ou.host_key = host ? host_key : 0;
        ou.user2 = user2;
        ou.user2_key = user2 ? user_key_fast(user2) : 0;
        ou.load_defer = user2_session ? g_load_defer.load(std::memory_order_relaxed) : uint8_t{0};
        ou.user2_loading = ou.load_defer && user2_loading_now(now_ms());
        ou.pub_gate = g_pub_gate.load(std::memory_order_relaxed);
    }
    bool any_npc = false, any_char = false;
    for (size_t j = 0; j < c.keys.size(); ++j) {
        if (characters) {
            // child_hold's rule as configured (it may be off with character_hold alone).
            HoldRules rules;
            rules.children = children;
            rules.npc = observers ? &ou : nullptr;
            rules.characters = true;
            rules.fast = observers;
            verdicts[j] = hold_verdict_rules(*sam, c.keys[j], user2, host, host_key, user_vt, rules);
            if (verdicts[j].why == HoldWhy::NotMain) g_char_not_main.fetch_add(1, std::memory_order_relaxed);
        } else {
            verdicts[j] = observers ? hold_verdict_ex(*sam, c.keys[j], user2, host, host_key, user_vt, children, &ou)
                                    : hold_verdict(*sam, c.keys[j], user2, host, host_key, user_vt);
        }
        any_npc = any_npc || (verdicts[j].hold && verdicts[j].npc);
        any_char = any_char || (verdicts[j].hold && verdicts[j].character);
        if (verdicts[j].cc_unknown) {
            const bool held = verdicts[j].hold;
            (held ? g_pg_cc_unknown_held : g_pg_cc_unknown_would).fetch_add(1, std::memory_order_relaxed);
            note(g_pg_entry_logged, kMaxPubEntryLogged, kNotePubCcUnknown,
                 {c.keys[j], verdicts[j].type, verdicts[j].controller,
                  cc_state_with(game::FastReads{}, verdicts[j].actor).slot, static_cast<uint64_t>(!held)});
        }
        // observer_load_defer=probe: what would be withheld from user 2 (nothing is).
        if (verdicts[j].defer && !verdicts[j].hold) {
            g_ld_would.fetch_add(1, std::memory_order_relaxed);
            note(g_ld_logged, hold::kLoadDeferLogged, kNoteLoadWould,
                 {c.keys[j], verdicts[j].type, verdicts[j].controller, user2_session, ou.user2_key});
        }
    }
    // child_settle: a user's child that D-53 does not hold (restore != 0, or child_hold off) and whose
    // owner's main character goes in this call or was announced to a non-owner recipient just now.
    // The candidates whose character is not in the call nor recent are checked against character_hold's
    // table under the lock below (still withheld from a recipient -> settle too).
    struct SettleCand {
        size_t j = 0;
        SettleCandidate sc;
        bool need = false;
    };
    std::vector<SettleCand> settle_cands;
    const uint32_t settle_ms = g_settle_ms.load(std::memory_order_relaxed);
    if (settle_ms) {
        const uint64_t now = now_ms();
        for (size_t j = 0; j < c.keys.size(); ++j) {
            const HoldVerdict& v = verdicts[j];
            if (v.hold || (v.why != HoldWhy::Restored && v.why != HoldWhy::ChildrenOff)) continue;
            SettleCand sc;
            sc.j = j;
            sc.sc = settle_candidate(*sam, c.keys[j], user2, host, host_key, user_vt);
            if (!sc.sc.ok) continue;
            const bool in_call = std::find(c.keys.begin(), c.keys.end(), sc.sc.main_key) != c.keys.end();
            for (size_t i = 0; i < c.sessions.size() && !sc.need; ++i) {
                if (!c.sessions[i] || users[i] == sc.sc.owner) continue;
                const uint64_t last = g_announced.last(sc.sc.main_key, c.sessions[i]);
                // Never announced there: does that user see the character (it is coming) or not?
                const std::optional<bool> in_range =
                    last || in_call ? std::nullopt
                                    : main_in_range_with(game::FastReads{}, sc.sc.main_actor, users[i]);
                sc.need = cst::settle_needed(settle_ms, in_call, last, false, now, in_range);
            }
            HoldVerdict& w = verdicts[j];
            w.main_in_call = in_call;
            settle_cands.push_back(sc);
        }
    }
    if (any_npc || any_char || !settle_cands.empty()) {
        // Room for every (NPC or character, observer) this split may withhold,
        // taken now under the lock (other server-realm threads split too). One
        // whose observers do not all fit is left native (announced with restore
        // 0, as without the key), never withheld without an entry.
        auto observers_of = [&](const HoldVerdict& v) {
            size_t n = 0;
            for (size_t i = 0; i < c.sessions.size(); ++i) {
                if (c.sessions[i] && users[i] != v.owner) ++n;
            }
            return n;
        };
        std::lock_guard lock(g_mu);
        const size_t free_npc = g_npc_table.room() - std::min(g_npc_table.room(), g_npc_reserved);
        const size_t free_char = g_char_table.room() - std::min(g_char_table.room(), g_char_reserved);
        size_t used = 0, used_char = 0;
        for (size_t j = 0; j < c.keys.size(); ++j) {
            HoldVerdict& v = verdicts[j];
            if (!v.hold || (!v.npc && !v.character)) continue;
            const size_t n = observers_of(v);
            size_t& u = v.npc ? used : used_char;
            if (u + n > (v.npc ? free_npc : free_char)) {
                if (v.npc) {
                    g_npc_full.fetch_add(1, std::memory_order_relaxed);
                    // S35 publication_gate=1: a full table never turns an unsafe NPC into a native announcement; it is
                    // withheld WITHOUT an entry (record() skips it). probe: counted, announced as before.
                    const pubg::Mode gate = pub_gate();
                    if (gate != pubg::Mode::Off) {
                        const bool withhold = pubg::withhold_without_entry(gate);
                        (withhold ? g_pg_withheld_no_entry : g_pg_would_no_entry).fetch_add(1, std::memory_order_relaxed);
                        note(g_pg_entry_logged, kMaxPubEntryLogged, kNotePubNoEntry,
                             {c.keys[j], v.type, v.controller, 0, static_cast<uint64_t>(!withhold)});
                        if (withhold) {
                            v.no_entry = true;
                            continue;  // stays held (v.hold, v.npc): withheld from the others, no room taken
                        }
                    }
                    note(g_npc_other_logged, kMaxNpcOtherLogged, kNoteNpcTableFull, {c.keys[j], v.controller});
                } else {
                    g_char_full.fetch_add(1, std::memory_order_relaxed);
                    note(g_char_other_logged, kMaxCharOtherLogged, kNoteCharFull,
                         {c.keys[j], static_cast<uint64_t>(v.owner_who)});
                }
                v.hold = false;
                v.npc = false;
                v.character = false;
                v.why = HoldWhy::TableFull;
            } else {
                u += n;
            }
        }
        g_npc_reserved += used;
        g_char_reserved += used_char;
        reservation.n = used;
        reservation.chars = used_char;
        // child_settle: still withheld by character_hold from a recipient -> settles too; then the room.
        if (!settle_cands.empty()) {
            const size_t free_settle = g_settle_table.room() - std::min(g_settle_table.room(), g_settle_reserved);
            size_t used_settle = 0;
            for (SettleCand& sc : settle_cands) {
                for (size_t i = 0; i < c.sessions.size() && !sc.need; ++i) {
                    if (!c.sessions[i] || users[i] == sc.sc.owner) continue;
                    for (size_t x = 0; x < g_char_table.size() && !sc.need; ++x) {
                        const HoldEntry& ce = g_char_table.at(x);
                        sc.need = ce.key == sc.sc.main_key && ce.observer == c.sessions[i];
                    }
                }
                if (!sc.need) continue;
                HoldVerdict& v = verdicts[sc.j];
                v.owner = sc.sc.owner;
                v.owner_who = sc.sc.owner_who;
                v.actor = sc.sc.actor;
                v.type = sc.sc.type;
                v.main_key = sc.sc.main_key;
                v.restore = restore_byte_with(game::FastReads{}, sc.sc.actor).value_or(0xFF);
                const size_t n = observers_of(v);
                if (used_settle + n > free_settle) {
                    g_settle_full.fetch_add(1, std::memory_order_relaxed);
                    note(g_settle_other_logged, kMaxSettleOtherLogged, kNoteSettleFull,
                         {c.keys[sc.j], static_cast<uint64_t>(v.owner_who)});
                    continue;  // left native, as without the key
                }
                used_settle += n;
                v.hold = true;
                v.settle = true;
                v.why = HoldWhy::Hold;
            }
            g_settle_reserved += used_settle;
            reservation.settle = used_settle;
        }
    }
    // observer_hold_family: after every other rule's room (a parent left native for want of room takes its
    // members along; a parent withheld by any rule keeps them behind it).
    if (const uint8_t fm = observers ? g_family.load(std::memory_order_relaxed) : uint8_t{0}) {
        prepare_family(c, users, host, user2, verdicts, reservation, fm);
    }
    bool any = false;
    uintptr_t held_owner = 0;
    for (const HoldVerdict& v : verdicts) {
        if (v.hold && !held_owner) held_owner = v.owner;
        any = any || v.hold;
    }
    if (!any) return false;
    // One unreadable recipient: unchanged (the owner's session must never
    // miss its own child).
    if (unreadable_session) {
        g_unreadable.fetch_add(1, std::memory_order_relaxed);
        note(g_other_logged, kMaxOtherLogged, kNoteUnreadableSession,
             {unreadable_session, static_cast<uint64_t>(held_owner && held_owner == host)});
        pub_unchecked(1, c.keys.size());  // S35 review 11
        return false;
    }
    return plan_split(c.sessions, users, host, c.keys, verdicts, plan);
}

void forget(std::span<const uint32_t> keys, std::span<const uintptr_t> sessions) {
    if (keys.empty() || sessions.empty()) return;
    if (g_size.load(std::memory_order_relaxed)) {
        std::lock_guard lock(g_mu);
        const size_t gone = g_table.forget_announced(keys, sessions);
        g_size.store(g_table.size());
        if (gone) {
            g_forgotten.fetch_add(gone);
            note(g_other_logged, kMaxOtherLogged, kNoteChildForgotten, {gone});
        }
    }
    if (g_char_size.load(std::memory_order_relaxed)) {
        std::lock_guard lock(g_mu);
        const size_t gone = g_char_table.forget_announced(keys, sessions);
        g_char_size.store(g_char_table.size());
        if (gone) {
            g_char_forgotten.fetch_add(gone);
            note(g_char_other_logged, kMaxCharOtherLogged, kNoteCharForgotten, {gone});
        }
    }
    if (g_settle_size.load(std::memory_order_relaxed)) {
        std::lock_guard lock(g_mu);
        const size_t gone = g_settle_table.forget_announced(keys, sessions);
        g_settle_size.store(g_settle_table.size());
        if (gone) {
            g_settle_forgotten.fetch_add(gone);
            note(g_settle_other_logged, kMaxSettleOtherLogged, kNoteSettleForgotten, {gone});
        }
    }
    if (g_npc_size.load(std::memory_order_relaxed)) {
        // Sorted outside the lock: the table is binary-searched per entry.
        std::vector<uint32_t> sorted(keys.begin(), keys.end());
        std::sort(sorted.begin(), sorted.end());
        std::lock_guard lock(g_mu);
        const size_t gone = g_npc_table.forget_announced(sorted, sessions);
        g_npc_size.store(g_npc_table.size());
        if (gone) {
            g_npc_forgotten.fetch_add(gone);
            note(g_npc_other_logged, kMaxNpcOtherLogged, kNoteNpcForgotten, {gone});
        }
    }
    if (g_fam_size.load(std::memory_order_relaxed)) {
        // observer_hold_family: a member the engine announced itself (to the host's session, or when the split
        // could not withhold it). A long list is sorted outside the lock.
        std::vector<uint32_t> sorted;
        std::span<const uint32_t> listed = keys;
        if (keys.size() > 64) {
            sorted.assign(keys.begin(), keys.end());
            std::sort(sorted.begin(), sorted.end());
            listed = sorted;
        }
        std::lock_guard lock(g_mu);
        const size_t gone = g_fam_table.forget_announced(listed, sessions);
        g_fam_size.store(g_fam_table.size());
        if (gone) {
            g_fm_forgotten.fetch_add(gone);
            note(g_fm_other_logged, kMaxFamOtherLogged, kNoteFamOther, {5, gone});
        }
    }
}

// observer_hold: one NPC record (under g_mu). True = it is in the table now (added or refreshed).
bool record_npc_locked(const HoldRecord& r, uint32_t epoch, uint64_t now, uint32_t observer_key) {
    HoldEntry e;
    e.key = r.key;
    e.observer = r.observer;
    e.observer_user = r.observer_user;
    e.owner = r.owner;
    e.owner_who = r.owner_who;
    e.observer_host = r.observer_host;
    e.epoch = epoch;
    e.since_ms = now;
    e.type = r.type;
    e.npc = true;
    e.controller = r.controller;
    e.actor = r.actor;
    e.defer = r.defer;
    switch (g_npc_table.add(e)) {
        case NpcHoldTable::Add::Added:
            g_npc_held.fetch_add(1);
            (r.owner_who == OwnerWho::Host ? g_npc_held_host_ctrl : g_npc_held_user2_ctrl).fetch_add(1);
            if (r.defer) {
                // observer_load_defer: its own lines (the restore-0 hold lines keep their budget).
                g_ld_deferred.fetch_add(1);
                note(g_ld_logged, hold::kLoadDeferLogged, kNoteLoadDeferred,
                     {r.key, r.type, r.controller, r.observer, observer_key, epoch});
            } else {
                note(g_npc_hold_logged, kMaxNpcHoldLogged, kNoteNpcHeld,
                     {r.key, r.type, static_cast<uint64_t>(r.owner_who), r.controller, r.observer,
                      static_cast<uint64_t>(r.observer_host), observer_key, epoch});
            }
            return true;
        case NpcHoldTable::Add::Duplicate:
            g_npc_again.fetch_add(1);
            return true;
        case NpcHoldTable::Add::Full:
            // Cannot happen: prepare() reserved the room under this lock.
            g_npc_unrecorded.fetch_add(1);
            note(g_npc_other_logged, kMaxNpcOtherLogged, kNoteNpcFullAfterSplit, {r.key, r.observer});
            return false;
    }
    return false;
}

// character_hold: one character record (under g_mu). True = it is in the table now (added or refreshed).
bool record_char_locked(const HoldRecord& r, uint32_t epoch, uint64_t now, uint32_t observer_key, uint32_t owner_key) {
    HoldEntry e;
    e.key = r.key;
    e.observer = r.observer;
    e.observer_user = r.observer_user;
    e.owner = r.owner;
    e.owner_who = r.owner_who;
    e.observer_host = r.observer_host;
    e.epoch = epoch;
    e.since_ms = now;
    e.type = r.type;
    e.character = true;
    e.actor = r.actor;
    switch (g_char_table.add(e)) {
        case CharHoldTable::Add::Added:
            g_char_held.fetch_add(1);
            (r.owner_who == OwnerWho::Host ? g_char_held_host : g_char_held_user2).fetch_add(1);
            note(g_char_hold_logged, kMaxCharHoldLogged, kNoteCharHeld,
                 {r.key, r.type, static_cast<uint64_t>(r.owner_who), owner_key, r.observer,
                  static_cast<uint64_t>(r.observer_host), observer_key, epoch});
            return true;
        case CharHoldTable::Add::Duplicate:
            g_char_again.fetch_add(1);
            return true;
        case CharHoldTable::Add::Full:
            // Cannot happen: prepare() reserved the room under this lock.
            g_char_unrecorded.fetch_add(1);
            note(g_char_other_logged, kMaxCharOtherLogged, kNoteCharFullAfterSplit, {r.key, r.observer});
            return false;
    }
    return false;
}

// child_settle: one record (under g_mu). True = it is in the table now (added or refreshed).
bool record_settle_locked(const HoldRecord& r, uint32_t epoch, uint64_t now, uint32_t observer_key,
                          uint32_t owner_key) {
    HoldEntry e;
    e.key = r.key;
    e.observer = r.observer;
    e.observer_user = r.observer_user;
    e.owner = r.owner;
    e.owner_who = r.owner_who;
    e.observer_host = r.observer_host;
    e.epoch = epoch;
    e.since_ms = now;
    e.type = r.type;
    e.settle = true;
    e.main_key = r.main_key;
    e.actor = r.actor;
    switch (g_settle_table.add(e)) {
        case SettleHoldTable::Add::Added:
            g_settle_held.fetch_add(1);
            (r.owner_who == OwnerWho::Host ? g_settle_held_host : g_settle_held_user2).fetch_add(1);
            note(g_settle_hold_logged, kMaxSettleHoldLogged, kNoteSettleHeld,
                 {r.key, r.type, static_cast<uint64_t>(r.owner_who), owner_key, r.observer,
                  static_cast<uint64_t>(r.observer_host), observer_key, epoch, r.main_key, r.restore,
                  static_cast<uint64_t>(r.main_in_call), g_settle_ms.load(std::memory_order_relaxed)});
            return true;
        case SettleHoldTable::Add::Duplicate:
            g_settle_again.fetch_add(1);
            return true;
        case SettleHoldTable::Add::Full:
            g_settle_unrecorded.fetch_add(1);  // cannot happen: prepare() reserved the room under this lock
            note(g_settle_other_logged, kMaxSettleOtherLogged, kNoteSettleFull,
                 {r.key, static_cast<uint64_t>(r.owner_who)});
            return false;
    }
    return false;
}

// observer_hold_family: one member record (under g_mu). True = it is in the table now (added or refreshed).
bool record_family_locked(const HoldRecord& r, uint32_t epoch, uint64_t now, uint32_t observer_key) {
    HoldEntry e;
    e.key = r.key;
    e.observer = r.observer;
    e.observer_user = r.observer_user;
    e.owner = r.owner;
    e.owner_who = r.owner_who;
    e.observer_host = r.observer_host;
    e.epoch = epoch;
    e.since_ms = now;
    e.wait_since_ms = now;
    e.type = r.type;
    e.controller = r.controller;
    e.actor = r.actor;
    e.defer = r.defer;
    e.family = true;
    e.parent = r.parent;
    e.family_why = r.family_why;
    switch (g_fam_table.add(e)) {
        case FamilyHoldTable::Add::Added:
            g_fm_held.fetch_add(1);
            switch (static_cast<FamilyWhy>(r.family_why)) {
                case FamilyWhy::ParentInCall: g_fm_held_in_call.fetch_add(1); break;
                case FamilyWhy::ParentHeld: g_fm_held_held.fetch_add(1); break;
                default: g_fm_held_unknown.fetch_add(1); break;
            }
            note(g_fm_logged, kMaxFamLogged, kNoteFamHeld,
                 {r.key, r.type, r.parent, r.observer, static_cast<uint64_t>(r.observer_host), observer_key, epoch,
                  static_cast<uint64_t>(r.owner_who), r.family_why});
            return true;
        case FamilyHoldTable::Add::Duplicate:
            g_fm_again.fetch_add(1);
            return true;
        case FamilyHoldTable::Add::Full:
            // Cannot happen: prepare_family() reserved the room under this lock.
            g_fm_unrecorded.fetch_add(1);
            note(g_fm_other_logged, kMaxFamOtherLogged, kNoteFamOther, {1, r.key, r.observer});
            return false;
    }
    return false;
}

// observer_hold_acks (observer_hold_acks.h): the session whose NPC packets wait for their 2005 (the
// live session 2 as the OBSERVER; never the controller, which is never held). 0 = that key is off.
uintptr_t ack_session() { return observer_hold_acks_active() ? server_live_session2() : 0; }

// P8 review I5 (p8-revision-noche.md): the keys this split withholds from user 2's
// session are registered with observer_hold_acks BEFORE the split's native
// NotifyAppear calls (steps 1 and 2), so that no per-actor packet of them that
// another thread emits meanwhile passes before their 2005. The plan already has
// the verdicts. started: the hold is new (dropped again if the key is not recorded).
struct PreAck {
    uint32_t key = 0;
    bool started = false;
};

void pre_begin_acks(const SplitPlan& plan, std::vector<PreAck>& out) {
    const uintptr_t acks = ack_session();
    if (!acks) return;
    const uint32_t epoch = server_epoch();
    for (const HoldRecord& r : plan.records) {
        if (!(r.npc || r.character || r.settle || r.family) || r.observer_host || r.observer != acks) continue;
        // S35 publication_gate: withheld without an entry: no 2005 will come for it from a release; its packets reach
        // user 2's client as for any key it was never given (dropped there).
        if (r.no_entry) continue;
        // observer_load_defer: its packets are not kept (seconds of moves; the 2005 after the 2762 carries the
        // NPC's state then). They reach user 2's client as without the hold, which drops them (unknown key).
        if (r.defer) continue;
        if (std::any_of(out.begin(), out.end(), [&](const PreAck& a) { return a.key == r.key; })) continue;
        const oha::Begin b = observer_hold_acks_begin(r.key, epoch);
        if (b != oha::Begin::Full) out.push_back({r.key, b == oha::Begin::Started});
    }
}

void record(const SplitPlan& plan, NpcReservation& reservation, std::span<const PreAck> pre) {
    const uint64_t now = now_ms();
    const uint32_t epoch = server_epoch();
    for (const HoldGroup& g : plan.groups) {
        g_owner_sent.fetch_add(g.sessions.empty() ? 0 : g.keys.size());
        if (g.sessions.empty()) g_owner_absent.fetch_add(g.keys.size());
    }
    // The users' keys for the log lines, read before the lock.
    std::vector<uint32_t> obs_keys(plan.records.size()), owner_keys(plan.records.size());
    for (size_t i = 0; i < plan.records.size(); ++i) {
        const HoldRecord& r = plan.records[i];
        const bool fast = r.npc || r.family;
        obs_keys[i] = fast ? user_key_fast(r.observer_user) : user_key_of(r.observer_user);
        owner_keys[i] = fast ? 0 : user_key_of(r.owner);
    }
    // observer_hold_acks: the NPCs withheld from user 2's session (told after the lock).
    const uintptr_t acks = ack_session();
    std::vector<uint32_t> ack_keys;
    if (acks) ack_keys.reserve(plan.records.size());
    std::unique_lock lock(g_mu);
    for (size_t i = 0; i < plan.records.size(); ++i) {
        const HoldRecord& r = plan.records[i];
        if (observer_hold_acks_retired(r.key)) continue;
        if (r.no_entry) continue;  // S35 publication_gate: withheld without an entry (counted in prepare)
        if (r.npc) {
            if (record_npc_locked(r, epoch, now, obs_keys[i]) && acks && !r.observer_host && r.observer == acks &&
                !r.defer) {
                ack_keys.push_back(r.key);
            }
            continue;
        }
        if (r.family) {
            // A family member withheld from user 2 behind its parent: its per-actor packets wait for its 2005 too.
            if (record_family_locked(r, epoch, now, obs_keys[i]) && acks && !r.observer_host && r.observer == acks &&
                !r.defer) {
                ack_keys.push_back(r.key);
            }
            continue;
        }
        if (r.character) {
            // The host's character withheld from user 2: its per-actor packets wait for its 2005 too.
            if (record_char_locked(r, epoch, now, obs_keys[i], owner_keys[i]) && acks && !r.observer_host &&
                r.observer == acks) {
                ack_keys.push_back(r.key);
            }
            continue;
        }
        if (r.settle) {
            // The host's pet withheld from user 2: its 2697/2991/2404 wait for its own 2005 too.
            if (record_settle_locked(r, epoch, now, obs_keys[i], owner_keys[i]) && acks && !r.observer_host &&
                r.observer == acks) {
                ack_keys.push_back(r.key);
            }
            continue;
        }
        HoldEntry e;
        e.key = r.key;
        e.observer = r.observer;
        e.observer_user = r.observer_user;
        e.owner = r.owner;
        e.owner_who = r.owner_who;
        e.observer_host = r.observer_host;
        e.epoch = epoch;
        e.since_ms = now;
        e.type = r.type;
        switch (g_table.add(e)) {
            case HoldTable::Add::Added:
                g_held.fetch_add(1);
                (r.owner_who == OwnerWho::Host ? g_held_host : g_held_user2).fetch_add(1);
                note(g_hold_logged, kMaxHoldLogged, kNoteChildHeld,
                     {r.key, r.type, static_cast<uint64_t>(r.owner_who), owner_keys[i], r.observer,
                      static_cast<uint64_t>(r.observer_host), obs_keys[i], epoch});
                break;
            case HoldTable::Add::Duplicate:
                g_held_again.fetch_add(1);
                break;
            case HoldTable::Add::Full:
                g_unrecorded.fetch_add(1);
                note(g_other_logged, kMaxOtherLogged, kNoteChildFull, {r.key, r.observer});
                break;
        }
    }
    // The split's room is now its entries (or was not needed: duplicates).
    g_npc_reserved -= std::min(reservation.n, g_npc_reserved);
    reservation.n = 0;
    g_char_reserved -= std::min(reservation.chars, g_char_reserved);
    reservation.chars = 0;
    g_settle_reserved -= std::min(reservation.settle, g_settle_reserved);
    reservation.settle = 0;
    g_fam_reserved -= std::min(reservation.pieces, g_fam_reserved);
    reservation.pieces = 0;
    g_fam_size.store(g_fam_table.size());
    g_size.store(g_table.size());
    g_npc_size.store(g_npc_table.size());  // the passes skip everything while both read 0
    g_char_size.store(g_char_table.size());
    g_settle_size.store(g_settle_table.size());
    lock.unlock();
    // Registered before the native calls (pre_begin_acks); a key recorded but not registered then
    // (observer_hold_acks switched on meanwhile) is registered now, as before. A key registered
    // but not recorded (table full after the split) is let go again if its hold was new.
    for (const uint32_t k : ack_keys) {
        if (std::none_of(pre.begin(), pre.end(), [&](const PreAck& a) { return a.key == k; })) {
            (void)observer_hold_acks_begin(k, epoch);
        }
    }
    for (const PreAck& a : pre) {
        if (a.started && std::find(ack_keys.begin(), ack_keys.end(), a.key) == ack_keys.end()) {
            observer_hold_acks_drop(a.key);
        }
    }
}

// The threads on which the game itself calls NotifyAppear (the server's logic
// thread, where the handlers and loads run) are kept in g_native_tids
// (note_native_caller). The thread that runs OnRecvPacket and built session 2
// is NOT one (live C2 test 2026-10-09: T29232 vs the receiving thread).

void npc_periodic(bool allow_release, const char* where);
void family_delivered(std::span<const uint32_t> keys, std::span<const uintptr_t> sessions, bool allow_release,
                      const char* where);
void sweep_children(const char* where, bool count_deferred);
void char_pass(bool may_release, const char* where);
void settle_pass(bool may_release, const char* where);

// child_settle: the characters (0xA keys) this NotifyAppear announced, to these sessions (lock-free log).
void note_announced(std::span<const uint32_t> keys, std::span<const uintptr_t> sessions) noexcept {
    uint64_t now = 0;
    for (const uint32_t k : keys) {
        if ((k >> 28) != hold::kCharKeyClass) continue;
        if (!now) now = now_ms();
        for (const uintptr_t s : sessions) {
            if (!s) continue;
            g_announced.note(k, s, now);
            g_settle_announced.fetch_add(1, std::memory_order_relaxed);
        }
    }
}

// NotifyAppear(u8 unused, {NwSession**, u32}*, {u32*, u32}*). Nothing may
// throw out of here; any doubt runs the original with the engine's arguments.
void __fastcall notify_detour(uintptr_t flag, const GameVec* sessions, const GameVec* keys) noexcept {
    child_hold_settle_births();  // S33 review: a retired key born again, before any retired-key filter
    NpcPublicationScope publication;
    note_native_caller(reinterpret_cast<uintptr_t>(_ReturnAddress()));
    g_appear_tid.store(cur_tid(), std::memory_order_relaxed);
    g_calls.fetch_add(1, std::memory_order_relaxed);
    CallView c;
    SplitPlan plan;
    NpcReservation reservation;
    bool split = false;
    const bool observers = g_observers.load(std::memory_order_relaxed);
    const uint64_t t0 = observers ? qpc_us() : 0;
    try {
        if (read_call(sessions, keys, c)) {
            if (publication.active()) {
                std::erase_if(c.keys, [](uint32_t key) { return retired_for_publication(key); });
            }
            split = !c.keys.empty() && prepare(c, plan, reservation);
        }
    } catch (...) {
        g_errors.fetch_add(1, std::memory_order_relaxed);
        split = false;
        pub_unchecked(2, c.keys.size());  // S35 review 11
    }
    if (observers) store_max(g_prepare_us_max, qpc_us() - t0);
    const bool settle_on = g_settle_ms.load(std::memory_order_relaxed) != 0;
    if (!split) {
        reservation.give_back();
        call_notify(flag, sessions, keys);
        try {
            if (c.read) forget(c.keys, c.sessions);
            if (c.read && settle_on) note_announced(c.keys, c.sessions);
            // observer_hold_family: user 2 has these now; whatever waited behind one of them follows at once.
            if (c.read && observers && g_family.load(std::memory_order_relaxed)) {
                family_delivered(c.keys, c.sessions, server_realm(), "right after the engine announced its parent");
            }
        } catch (...) {
        }
    } else {
        g_split.fetch_add(1, std::memory_order_relaxed);
        // 0. observer_hold_acks: the withheld keys are held from now (P8 review I5).
        std::vector<PreAck> pre;
        try {
            pre_begin_acks(plan, pre);
        } catch (...) {
            g_errors.fetch_add(1, std::memory_order_relaxed);
        }
        // 1. The other keys to every recipient (the engine's own sessions struct),
        //    in their order: a mixed 2005 keeps its parent -> child order.
        if (!plan.pass.empty()) {
            const GameVec k{plan.pass.data(), static_cast<uint32_t>(plan.pass.size()),
                            static_cast<uint32_t>(plan.pass.size())};
            call_notify(flag, sessions, &k);
        }
        // 2. Each owner gets its held children now, in a 2005 of their own.
        for (const HoldGroup& g : plan.groups) {
            if (g.sessions.empty()) continue;
            const GameVec s{g.sessions.data(), static_cast<uint32_t>(g.sessions.size()),
                            static_cast<uint32_t>(g.sessions.size())};
            const GameVec k{g.keys.data(), static_cast<uint32_t>(g.keys.size()), static_cast<uint32_t>(g.keys.size())};
            call_notify(flag, &s, &k);
        }
        // 3. Everyone else waits for the child's first action.
        try {
            forget(plan.pass, c.sessions);
            if (settle_on) {
                // child_settle: the characters that went out now, to whom (never one withheld from a session).
                note_announced(plan.pass, c.sessions);
                for (const HoldGroup& g : plan.groups) note_announced(g.keys, g.sessions);
            }
            record(plan, reservation, pre);
            // observer_hold_family: what user 2 got now (the pass, its own groups); what waited behind it follows.
            if (observers && g_family.load(std::memory_order_relaxed)) {
                const bool realm = server_realm();
                family_delivered(plan.pass, c.sessions, realm, "right after the engine announced its parent");
                for (const HoldGroup& g : plan.groups) {
                    family_delivered(g.keys, g.sessions, realm, "right after the engine announced its parent");
                }
            }
        } catch (...) {
            g_errors.fetch_add(1, std::memory_order_relaxed);
        }
    }
    // child_settle: the entries whose character settled go now (this is a native NotifyAppear thread).
    if (settle_on && g_settle_size.load(std::memory_order_relaxed)) {
        try {
            const uint64_t now = now_ms();
            uint64_t last = g_settle_last_pass.load(std::memory_order_relaxed);
            if (now - last >= hold::kCharPassMs &&
                g_settle_last_pass.compare_exchange_strong(last, now, std::memory_order_relaxed)) {
                settle_pass(true, "after NotifyAppear");
            }
        } catch (...) {
            g_errors.fetch_add(1, std::memory_order_relaxed);
        }
    }
    // observer_hold (M5): the game's own NotifyAppear thread is where a
    // release is legitimate; the budgeted pass runs here too, so NPC entries
    // progress (timeouts, deferred releases) without any StartActionReq.
    if (observers && (g_npc_size.load(std::memory_order_relaxed) || g_fam_size.load(std::memory_order_relaxed) ||
                      g_pub_shadow_size.load(std::memory_order_relaxed))) {
        try {
            if (server_realm()) npc_periodic(true, "after NotifyAppear");
        } catch (...) {
            g_errors.fetch_add(1, std::memory_order_relaxed);
        }
    }
    // The thread rule: the releases a StartActionReq on another thread had to
    // leave (and the characters' timeouts) happen here, on the game's own
    // NotifyAppear thread, at most every 50 ms each. The children's sweep only
    // with notify_thread_rule=1 (with 0 D-53 is exactly as before the rule).
    if (g_size.load(std::memory_order_relaxed) || g_char_size.load(std::memory_order_relaxed)) {
        try {
            const uint64_t now = now_ms();
            if (g_size.load(std::memory_order_relaxed) && g_thread_rule.load(std::memory_order_relaxed)) {
                uint64_t last = g_child_tail_tick.load(std::memory_order_relaxed);
                if (now - last >= kTickMs &&
                    g_child_tail_tick.compare_exchange_strong(last, now, std::memory_order_relaxed)) {
                    sweep_children("after NotifyAppear", false);
                }
            }
            if (g_char_size.load(std::memory_order_relaxed)) {
                uint64_t last = g_char_last_pass.load(std::memory_order_relaxed);
                if (now - last >= hold::kCharPassMs &&
                    g_char_last_pass.compare_exchange_strong(last, now, std::memory_order_relaxed)) {
                    char_pass(true, "after NotifyAppear");
                }
            }
        } catch (...) {
            g_errors.fetch_add(1, std::memory_order_relaxed);
        }
    }
}

struct Due {
    uint32_t key;
    uintptr_t observer;
    uint32_t observer_key;
    uint64_t age_ms;
    uint8_t type;
    OwnerWho owner_who;
    bool observer_host;
};

// Under g_mu, once user 2 is gone or leaving: its entries (as the owner or as
// the observer) go, never published. Returns what is left (with two users,
// nothing: a host-owned child is only ever withheld from user 2).
size_t drop_user2_locked(bool present) {
    const size_t n = g_table.drop_user2_entries();
    g_size.store(g_table.size());
    if (n) {
        g_cleared.fetch_add(n);
        note(g_other_logged, kMaxOtherLogged, kNoteChildUser2Drop, {static_cast<uint64_t>(present), n, g_table.size()});
    }
    return g_table.size();
}

// observer_hold: under g_mu, once user 2 is gone or leaving: the NPC entries
// it observes go (npc_entry_of_leaving_user2).
size_t drop_npc_user2_locked(bool present) {
    const size_t n = g_npc_table.drop_if([](const HoldEntry& e) { return npc_entry_of_leaving_user2(e); });
    g_npc_size.store(g_npc_table.size());
    if (n) {
        g_npc_cleared.fetch_add(n);
        note(g_npc_other_logged, kMaxNpcOtherLogged, kNoteNpcUser2Drop,
             {static_cast<uint64_t>(present), n, g_npc_table.size()});
    }
    // observer_hold_family: the members withheld from it go with their parents.
    const size_t np = g_fam_table.drop_if([](const HoldEntry& e) { return npc_entry_of_leaving_user2(e); });
    g_fam_size.store(g_fam_table.size());
    if (np) {
        g_fm_cleared.fetch_add(np);
        note(g_fm_other_logged, kMaxFamOtherLogged, kNoteFamOther,
             {4, static_cast<uint64_t>(present), np, g_fam_table.size()});
    }
    return g_npc_table.size() + g_fam_table.size();
}

// child_settle, under g_mu: D-53's release of `e` (restore 1 now) waits while the owner's main
// character is still withheld from the observer (character_hold) or was announced there less than
// child_settle_ms ago (the same rule as a split; pendientes/p8-impl-mascotas.md §2.3).
std::atomic<uint64_t> g_settle_d53_logged{0};
bool d53_waits_settle(uintptr_t sam, const HoldEntry& e, uint64_t now, uintptr_t user2, uintptr_t host,
                      uint32_t host_key) {
    const uint32_t ms = g_settle_ms.load(std::memory_order_relaxed);
    if (!ms) return false;
    const uintptr_t user_vt = user_vtable_now();
    const SettleCandidate sc = settle_candidate(sam, e.key, user2, host, host_key, user_vt);
    if (!sc.ok) return false;
    bool held = false;
    for (size_t x = 0; x < g_char_table.size() && !held; ++x) {
        held = g_char_table.at(x).key == sc.main_key && g_char_table.at(x).observer == e.observer;
    }
    const uint64_t last = g_announced.last(sc.main_key, e.observer);
    const std::optional<bool> in_range =
        last || held ? std::nullopt : main_in_range_with(game::FastReads{}, sc.main_actor, e.observer_user);
    if (!cst::settle_needed(ms, false, last, held, now, in_range)) return false;
    g_settle_d53_waited.fetch_add(1, std::memory_order_relaxed);
    note(g_settle_d53_logged, 16, kNoteSettleD53, {e.key, e.observer, sc.main_key, static_cast<uint64_t>(held)});
    return true;
}

// D-53: the children's sweep (no lock of ours is held during the native call;
// the game holds none at the call points). Only on a thread the game itself
// used for NotifyAppear (p8-auditoria-hilos.md §4 case 3): right after the
// StartActionReq handler when that thread is one (the engine reaches
// NotifyAppear from its handlers: an action that changes the actor's sector,
// 0x2AF8090), else at the tail of the next native NotifyAppear. The game runs
// several server-realm threads (live D-53r test 2026-10-09: "sweeps refused 4"
// after the child's first action with the old "last caller" test); the
// receiving thread's fallback is not one of them (T29232). count_deferred: a
// StartActionReq's sweep refused here (its release waits for the tail).
void sweep_children(const char* where, bool count_deferred) {
    if (!g_active.load(std::memory_order_relaxed) || !g_size.load(std::memory_order_relaxed)) return;
    // count_deferred: called right after the StartActionReq handler, on its thread.
    if (!server_realm() || !may_notify_here(count_deferred)) {
        g_sweep_other.fetch_add(1, std::memory_order_relaxed);
        if (count_deferred) {
            g_child_deferred.fetch_add(1, std::memory_order_relaxed);
            g_defer.deferred(now_ms(), cur_tid(), hold::DeferWatch::kChild);
        }
        return;
    }
    const uint64_t now = now_ms();
    g_defer.ran(now);  // a release may happen here: whatever waited for such a thread is taken now
    uintptr_t user2 = 0;
    const bool present = server_user2(user2);
    const bool leaving = server_logout_handed();
    const uint32_t settle_ms = g_settle_ms.load(std::memory_order_relaxed);
    uintptr_t host = 0;
    const uint32_t host_key = settle_ms ? host_key_now(host) : 0;
    std::array<Due, hold::kTableCapacity> due{};
    size_t n_due = 0;
    {
        std::lock_guard lock(g_mu);
        // User 2 left, is leaving, or its epoch ended: nothing of it is
        // published any more, and nothing is published to it.
        if (hold_drop_user2(present, leaving) && !drop_user2_locked(present)) return;
        const auto sam = sam_now(false);
        if (!sam) return;
        const uint32_t epoch = server_epoch();
        for (size_t i = 0; i < g_table.size();) {
            HoldEntry& e = g_table.at(i);
            ReleaseReadings r = read_child_release(*sam, e.key, e.observer_user);
            r.epoch_now = epoch;
            r.observer_valid = server_session_user(e.observer, r.observer_user);
            const char* why = "";
            const ReleaseStep step = release_step(e, r, why);
            const uint64_t age = now - e.since_ms;
            if (step == ReleaseStep::Keep) {
                if (r.restore && *r.restore == 0 && !e.timeout_noted && age >= hold::kTimeoutMs) {
                    e.timeout_noted = true;
                    g_timeouts.fetch_add(1);
                    note(g_other_logged, kMaxOtherLogged, kNoteChildTimeout,
                         {e.key, static_cast<uint64_t>(e.owner_who), e.observer,
                          static_cast<uint64_t>(e.observer_host), age});
                }
                ++i;
                continue;
            }
            if (step == ReleaseStep::Release && settle_ms && d53_waits_settle(*sam, e, now, user2, host, host_key)) {
                ++i;  // child_settle: its owner's character is new to the observer; released by a later sweep
                continue;
            }
            if (step == ReleaseStep::Release) {
                due[n_due++] = {e.key, e.observer, user_key_of(e.observer_user), age, e.type, e.owner_who,
                                e.observer_host};
            } else {
                g_dropped.fetch_add(1);
                note(g_other_logged, kMaxOtherLogged, kNoteChildDropped, {e.key, e.observer, age, ptr_bits(why)});
            }
            g_table.remove_at(i);
        }
        g_size.store(g_table.size());
    }
    for (size_t i = 0; i < n_due; ++i) {
        const Due& d = due[i];
        const uintptr_t session = d.observer;
        const uint32_t key = d.key;
        const GameVec s{&session, 1, 1};
        const GameVec k{&key, 1, 1};
        call_notify(0, &s, &k);  // the engine's own call, once, now with the action
        g_released.fetch_add(1);
        note(g_release_logged, kMaxReleaseLogged, kNoteChildReleased,
             {key, d.type, static_cast<uint64_t>(d.owner_who), session, static_cast<uint64_t>(d.observer_host),
              d.observer_key, d.age_ms, ptr_bits(where)});
    }
}

// ---------------------------------------------------------------- character_hold: the pass

// Under g_mu, once user 2 is gone or leaving: every character entry it is part
// of (its character withheld from the host, or the host's withheld from it).
size_t drop_char_user2_locked(bool present) {
    const size_t n = g_char_table.drop_user2_entries();
    g_char_size.store(g_char_table.size());
    if (n) {
        g_char_cleared.fetch_add(n);
        note(g_char_other_logged, kMaxCharOtherLogged, kNoteCharUser2Drop,
             {static_cast<uint64_t>(present), n, g_char_table.size()});
    }
    return g_char_table.size();
}

std::atomic_flag g_char_busy;  // one pass at a time (clear, C++20)

// The whole (small) table: copied under the lock, decided outside it with SEH
// reads by key, applied under the lock to the entries still there unchanged
// (stamp). may_release: the caller may call NotifyAppear (it is also checked
// here: a server-realm thread the game itself used for NotifyAppear); else a
// due release is left for the next pass that may (counted as deferred).
void char_pass(bool may_release, const char* where) {
    if (!g_char_size.load(std::memory_order_relaxed)) return;
    if (g_char_busy.test_and_set(std::memory_order_acquire)) return;
    struct Busy {
        ~Busy() { g_char_busy.clear(std::memory_order_release); }
    } busy;
    // With notify_thread_rule=0 the callers that may release are the StartActionReq
    // handler's thread and the tail of a native NotifyAppear (as D-53 before the rule).
    const bool release_ok = may_release && server_realm() &&
                            (!g_thread_rule.load(std::memory_order_relaxed) || native_appear_thread());
    {
        uintptr_t user2 = 0;
        const bool present = server_user2(user2);
        if (hold_drop_user2(present, server_logout_handed())) {
            std::lock_guard lock(g_mu);
            if (!drop_char_user2_locked(present)) return;
        }
    }
    const auto sam = sam_now(true);
    if (!sam) return;
    const uint64_t now = now_ms();
    if (release_ok) g_defer.ran(now);
    const uint32_t epoch = server_epoch();
    struct Snap {
        HoldEntry e;
        size_t index = 0;
        ReleaseStep step = ReleaseStep::Keep;
        CharRelease kind = CharRelease::None;
        const char* why = "";
        uint64_t age = 0;
        uint32_t observer_key = 0;
        bool note_slow = false;
        bool applied = false;
    };
    std::array<Snap, hold::kCharTableCapacity> snap{};
    size_t n = 0;
    {
        std::lock_guard lock(g_mu);
        for (size_t i = 0; i < g_char_table.size() && n < snap.size(); ++i) {
            snap[n].e = g_char_table.at(i);
            snap[n].index = i;
            ++n;
        }
    }
    for (size_t k = 0; k < n; ++k) {
        Snap& s = snap[k];
        uintptr_t obs_user = 0;
        const bool valid = server_session_user(s.e.observer, obs_user);
        CharReleaseReadings r = read_char_release(*sam, s.e.key, s.e.observer_user);
        r.epoch_now = epoch;
        r.observer_valid = valid;
        r.observer_user = obs_user;
        s.age = now >= s.e.since_ms ? now - s.e.since_ms : 0;
        s.step = char_release_step(s.e, r, s.age, s.why, &s.kind);
        s.observer_key = valid ? user_key_fast(obs_user) : 0;
        if (s.step == ReleaseStep::Release && !release_ok) {
            s.step = ReleaseStep::Keep;  // released by the next pass on a NotifyAppear thread
            g_char_deferred.fetch_add(1, std::memory_order_relaxed);
            g_defer.deferred(now, cur_tid(), hold::DeferWatch::kChar);
        }
        if (s.step == ReleaseStep::Keep) s.note_slow = !s.e.timeout_noted && s.age >= hold::kTimeoutMs;
    }
    // Highest index first: a removal moves the last entry into its place.
    std::array<size_t, hold::kCharTableCapacity> order{};
    for (size_t k = 0; k < n; ++k) order[k] = k;
    std::sort(order.begin(), order.begin() + static_cast<ptrdiff_t>(n),
              [&](size_t a, size_t b) { return snap[a].index > snap[b].index; });
    {
        std::lock_guard lock(g_mu);
        for (size_t x = 0; x < n; ++x) {
            Snap& s = snap[order[x]];
            if (s.step == ReleaseStep::Keep && !s.note_slow) continue;
            const size_t i = g_char_table.locate(s.e.stamp, s.index);
            if (i >= g_char_table.size()) continue;  // gone or refreshed meanwhile: decided again next time
            s.applied = true;
            if (s.step == ReleaseStep::Keep) {
                g_char_table.at(i).timeout_noted = true;
                continue;
            }
            g_char_table.remove_at(i);
        }
        g_char_size.store(g_char_table.size());
    }
    const uintptr_t acks = ack_session();
    for (size_t k = 0; k < n; ++k) {
        const Snap& s = snap[k];
        if (!s.applied) continue;
        const HoldEntry& e = s.e;
        if (s.step == ReleaseStep::Keep) {
            note(g_char_other_logged, kMaxCharOtherLogged, kNoteCharStill,
                 {e.key, static_cast<uint64_t>(e.owner_who), e.observer, static_cast<uint64_t>(e.observer_host), s.age,
                  ptr_bits(s.why)});
            continue;
        }
        if (s.step == ReleaseStep::Drop) {
            g_char_dropped.fetch_add(1);
            note(g_char_other_logged, kMaxCharOtherLogged, kNoteCharDropped,
                 {e.key, static_cast<uint64_t>(e.owner_who), e.observer, static_cast<uint64_t>(e.observer_host), s.age,
                  ptr_bits(s.why)});
            // observer_hold_acks: no 2005 will come for it: what was kept for it goes.
            if (acks && e.observer == acks) observer_hold_acks_drop(e.key);
            continue;
        }
        // Release: the engine's own call, once, to that observer only (a fresh 2005).
        const uintptr_t session = e.observer;
        const uint32_t key = e.key;
        const GameVec sv{&session, 1, 1};
        const GameVec kv{&key, 1, 1};
        call_notify(0, &sv, &kv);
        if (acks && session == acks) observer_hold_acks_released(std::span<const uint32_t>(&key, 1));
        // child_settle: the character reaches this observer now; its children settle from here.
        if (g_settle_ms.load(std::memory_order_relaxed)) note_announced(std::span<const uint32_t>(&key, 1),
                                                                        std::span<const uintptr_t>(&session, 1));
        g_char_released.fetch_add(1);
        if (s.kind == CharRelease::Restore1) g_char_restore1.fetch_add(1);
        if (s.kind == CharRelease::Timeout) g_char_timeouts.fetch_add(1);
        if (s.kind == CharRelease::Native) g_char_native.fetch_add(1);
        store_max(g_char_age_max, s.age);
        note(g_char_release_logged, kMaxCharReleaseLogged, kNoteCharReleased,
             {key, e.type, static_cast<uint64_t>(e.owner_who), session, static_cast<uint64_t>(e.observer_host),
              s.observer_key, s.age, static_cast<uint64_t>(s.kind), ptr_bits(where), ptr_bits(s.why)});
    }
}

// ---------------------------------------------------------------- child_settle: the pass

// Under g_mu, once user 2 is gone or leaving: every settle entry it is part of.
size_t drop_settle_user2_locked(bool present) {
    const size_t n = g_settle_table.drop_user2_entries();
    g_settle_size.store(g_settle_table.size());
    if (n) {
        g_settle_cleared.fetch_add(n);
        note(g_settle_other_logged, kMaxSettleOtherLogged, kNoteSettleUser2Drop,
             {static_cast<uint64_t>(present), n, g_settle_table.size()});
    }
    return g_settle_table.size();
}

std::atomic_flag g_settle_busy;  // one pass at a time (clear, C++20)

// As char_pass: the whole (small) table copied under the lock (with whether character_hold still
// withholds each one's character from its observer), decided outside it with SEH reads by key
// (cst::release_step), applied under the lock to the entries still there unchanged (stamp).
// may_release: the caller may call NotifyAppear (the StartActionReq handler's thread or the tail of a
// native NotifyAppear; with notify_thread_rule=1 only a native NotifyAppear thread); else (the receiving
// thread's fallback) as D-53's fallback: only on the last thread that called NotifyAppear (rule 0) or a
// native one (rule 1). A due release that cannot go waits for the next pass that may (counted as
// deferred); with notify_thread_rule=0, one that has waited hold::kDeferWarnMs (no StartActionReq nor
// NotifyAppear meanwhile: a quiet world) is released by the fallback itself, a server-realm thread.
// After each release, an entry of the same (child, observer) that a split recorded while the native call
// ran (a re-hold racing the release) is dropped: that 2005 is the one just sent.
void settle_pass(bool may_release, const char* where) {
    if (!g_settle_size.load(std::memory_order_relaxed)) return;
    if (g_settle_busy.test_and_set(std::memory_order_acquire)) return;
    struct Busy {
        ~Busy() { g_settle_busy.clear(std::memory_order_release); }
    } busy;
    const uint32_t settle_ms = g_settle_ms.load(std::memory_order_relaxed);
    const bool rule = g_thread_rule.load(std::memory_order_relaxed);
    const bool realm = server_realm();
    const bool release_ok =
        realm && (may_release ? (!rule || native_appear_thread()) : may_notify_here(/*on_handler_thread=*/false));
    const bool overdue_ok = realm && !may_release && !rule;  // the quiet-world last resort (rule 0 only)
    {
        uintptr_t user2 = 0;
        const bool present = server_user2(user2);
        if (hold_drop_user2(present, server_logout_handed())) {
            std::lock_guard lock(g_mu);
            if (!drop_settle_user2_locked(present)) return;
        }
    }
    const auto sam = sam_now(true);
    if (!sam) return;
    const uint64_t now = now_ms();
    if (release_ok) g_defer.ran(now);
    const uint32_t epoch = server_epoch();
    struct Snap {
        HoldEntry e;
        size_t index = 0;
        bool main_held = false;
        cst::Step step = cst::Step::Keep;
        cst::Kind kind = cst::Kind::None;
        const char* why = "";
        uint64_t age = 0;
        uint32_t observer_key = 0;
        bool applied = false;
        bool mark_deferred = false;  // a due release left for an allowed thread: its first moment noted
        bool overdue = false;        // released by the fallback after waiting hold::kDeferWarnMs
    };
    std::array<Snap, hold::kSettleTableCapacity> snap{};
    size_t n = 0;
    {
        std::lock_guard lock(g_mu);
        for (size_t i = 0; i < g_settle_table.size() && n < snap.size(); ++i) {
            snap[n].e = g_settle_table.at(i);
            snap[n].index = i;
            for (size_t x = 0; x < g_char_table.size() && !snap[n].main_held; ++x) {
                snap[n].main_held = g_char_table.at(x).key == snap[n].e.main_key &&
                                    g_char_table.at(x).observer == snap[n].e.observer;
            }
            ++n;
        }
    }
    const game::FastReads m;
    for (size_t k = 0; k < n; ++k) {
        Snap& s = snap[k];
        cst::Readings r;
        r.epoch_same = s.e.epoch == epoch;
        r.actor = find_actor_with(m, *sam, s.e.key);
        r.actor_then = s.e.actor;
        r.owner_then = s.e.owner;
        if (r.actor && *r.actor) {
            r.owner = m.rd<uintptr_t>(*r.actor + hold::kActorOwner);
            if (const auto sector = sector_with(m, *r.actor)) r.observes = observed_by_with(m, *sector, s.e.observer_user);
        }
        uintptr_t obs_user = 0;
        r.observer_valid = server_session_user(s.e.observer, obs_user) && obs_user == s.e.observer_user;
        r.main_held = s.main_held;
        r.main_last_ms = g_announced.last(s.e.main_key, s.e.observer);
        if (!r.main_last_ms && !s.main_held) {
            // Never announced there: is the character in that user's range (then it is coming)?
            if (const auto main = find_actor_with(m, *sam, s.e.main_key); main && *main) {
                r.main_in_range = main_in_range_with(m, *main, s.e.observer_user);
            }
        }
        r.since_ms = s.e.since_ms;
        r.not_before_ms = s.e.not_before_ms;
        r.now_ms = now;
        s.age = now >= s.e.since_ms ? now - s.e.since_ms : 0;
        s.step = cst::release_step(r, settle_ms, s.why, &s.kind);
        s.observer_key = r.observer_valid ? user_key_fast(obs_user) : 0;
        if (s.step == cst::Step::Release && !release_ok) {
            if (overdue_ok && s.e.deferred_since && now - s.e.deferred_since >= hold::kDeferWarnMs) {
                s.overdue = true;  // nothing else came to release it: the fallback does
            } else {
                s.step = cst::Step::Keep;  // released by the next pass on an allowed thread
                s.mark_deferred = !s.e.deferred_since;
                g_settle_deferred.fetch_add(1, std::memory_order_relaxed);
                g_defer.deferred(now, cur_tid(), hold::DeferWatch::kChild);
            }
        }
    }
    std::array<size_t, hold::kSettleTableCapacity> order{};
    for (size_t k = 0; k < n; ++k) order[k] = k;
    std::sort(order.begin(), order.begin() + static_cast<ptrdiff_t>(n),
              [&](size_t a, size_t b) { return snap[a].index > snap[b].index; });
    {
        std::lock_guard lock(g_mu);
        for (size_t x = 0; x < n; ++x) {
            Snap& s = snap[order[x]];
            if (s.step == cst::Step::Keep && !s.mark_deferred) continue;
            const size_t i = g_settle_table.locate(s.e.stamp, s.index);
            if (i >= g_settle_table.size()) continue;  // gone or refreshed meanwhile: decided again next time
            if (s.step == cst::Step::Keep) {
                g_settle_table.at(i).deferred_since = now;
                continue;
            }
            s.applied = true;
            g_settle_table.remove_at(i);
        }
        g_settle_size.store(g_settle_table.size());
    }
    const uintptr_t acks = ack_session();
    for (size_t k = 0; k < n; ++k) {
        const Snap& s = snap[k];
        if (!s.applied) continue;
        const HoldEntry& e = s.e;
        if (s.step == cst::Step::Drop) {
            g_settle_dropped.fetch_add(1);
            note(g_settle_other_logged, kMaxSettleOtherLogged, kNoteSettleDropped,
                 {e.key, static_cast<uint64_t>(e.owner_who), e.observer, static_cast<uint64_t>(e.observer_host), s.age,
                  ptr_bits(s.why)});
            if (acks && e.observer == acks) observer_hold_acks_drop(e.key);  // no 2005 will come for it
            continue;
        }
        // Release: the engine's own call, once, to that observer only (a fresh 2005, serialised now).
        const uintptr_t session = e.observer;
        const uint32_t key = e.key;
        const GameVec sv{&session, 1, 1};
        const GameVec kv{&key, 1, 1};
        call_notify(0, &sv, &kv);
        // A split that withheld the same child from the same observer while that call ran (the entry was
        // already out of the table): its 2005 is the one just sent, so that entry goes, never a second one.
        size_t raced = 0;
        {
            std::lock_guard lock(g_mu);
            raced = g_settle_table.drop_if(
                [&](const HoldEntry& x) { return x.key == key && x.observer == session && x.stamp > e.stamp; });
            g_settle_size.store(g_settle_table.size());
        }
        if (raced) g_settle_raced.fetch_add(raced);
        if (acks && session == acks) observer_hold_acks_released(std::span<const uint32_t>(&key, 1));
        if (s.overdue) g_settle_fallback.fetch_add(1);
        g_settle_released.fetch_add(1);
        if (s.kind == cst::Kind::Settled) g_settle_settled.fetch_add(1);
        if (s.kind == cst::Kind::MaxWait) g_settle_max_wait.fetch_add(1);
        if (s.kind == cst::Kind::Native) g_settle_native.fetch_add(1);
        store_max(g_settle_age_max, s.age);
        note(g_settle_release_logged, kMaxSettleReleaseLogged, kNoteSettleReleased,
             {key, e.type, static_cast<uint64_t>(e.owner_who), session, static_cast<uint64_t>(e.observer_host),
              s.observer_key, s.age, static_cast<uint64_t>(s.kind), ptr_bits(where), ptr_bits(s.why)});
    }
}

// ---------------------------------------------------------------- observer_hold: the passes (I1, I2, M5)

struct NpcSnap {
    HoldEntry e;
    size_t index;  // where it was when copied (a hint: re-located by its stamp)
};
struct NpcDecision {
    ReleaseStep step = ReleaseStep::Keep;
    NpcRelease kind = NpcRelease::None;
    const char* why = "";
    uint64_t age = 0;
    uint32_t controller_now = 0;
    uint32_t observer_key = 0;
    bool note_ctrl = false;   // the controller changed (noted once)
    bool note_slow = false;   // still held after hold::kTimeoutMs (noted once)
    bool note_u2 = false;     // withheld from the host past the timeout: user 2 controls it (noted once)
    bool applied = false;     // the entry was still there when re-locked
    // observer_hold_family: a release to user 2's session whose parent it has not got (and that is not released
    // in this pass): it waits for its parent as a family entry (converted), or goes now when the table is full.
    uint32_t parent = 0;
    bool present = false;
    bool blocked = false;
    uint8_t blocked_how = 0;  // 1 converted, 2 table full: released anyway, 3 probe: would wait
};
struct NpcDue {
    uint32_t key;
    uintptr_t observer;
    uint32_t observer_key;
    uint64_t age_ms;
    uint8_t type;
    bool observer_host;
    uint32_t controller;
    NpcRelease kind;
    const char* why;
    bool defer;   // observer_load_defer: held because user 2 was loading
    bool at_cap;  // ... and released while it still is (hold::kLoadDeferMaxMs)
    // observer_hold_family: a member (behind its parent in the same 2005), its parent and why it goes now.
    bool family = false;
    uint32_t parent = 0;
    FamilyRelease fkind = FamilyRelease::None;
    bool npc_origin = false;  // an observer_hold entry that waited for its parent: its NPC counters too
    uint8_t depth = 0;        // parents first: 0 = its parent is not in this release
    // S35 publication_gate: the entry this release took out of its table (put back if the gate refuses it).
    HoldEntry src{};
};

// One pass at a time (any thread): its buffers are static, nothing is
// allocated. A pass that finds another running is skipped and counted.
std::atomic_flag g_npc_busy;  // clear (C++20)
NpcSnap g_snap[hold::kNpcPassBudget];
NpcDecision g_dec[hold::kNpcPassBudget];
uint16_t g_order[hold::kNpcPassBudget];
// The releases of one pass: its NPCs (at most its budget) and every member of the family table (behind a parent
// released now, or on its own): each member leaves the table once.
constexpr size_t kDueCapacity = hold::kNpcPassBudget + hold::kFamilyTableCapacity;
NpcDue g_due[kDueCapacity];
uint32_t g_due_keys[kDueCapacity];
// observer_hold_family: the periodic pass's copy of the family table and the members dropped with their parents.
struct FamSnap {
    HoldEntry e;
    size_t index = 0;
    bool parent_held = false;   // its parent had an entry withheld from this observer when copied (any table)
    bool tracks = false;        // the observer is user 2's tracked session
    bool parent_known = false;  // ... and its parent had been announced there
    ReleaseStep step = ReleaseStep::Keep;
    FamilyRelease kind = FamilyRelease::None;
    const char* why = "";
    uint64_t age = 0;
    uint64_t wait = 0;
    uint32_t observer_key = 0;
    bool applied = false;
};
FamSnap g_psnap[hold::kFamilyTableCapacity];
HoldEntry g_pgone[hold::kFamilyTableCapacity];
// observer_hold_family: every (key, observer) withheld now, sorted (the members' "parent still withheld").
struct HeldKey {
    uint32_t key;
    uintptr_t observer;
    bool operator<(const HeldKey& o) const { return key != o.key ? key < o.key : observer < o.observer; }
};
constexpr size_t kHeldIndexCapacity =
    hold::kNpcTableCapacity + hold::kFamilyTableCapacity + hold::kTableCapacity + hold::kSettleTableCapacity;
HeldKey g_held_idx[kHeldIndexCapacity];
// The depth computation's index of a release batch (key, observer) -> position.
struct DueKey {
    uint32_t key;
    uintptr_t observer;
    uint32_t at;
    bool operator<(const DueKey& o) const { return key != o.key ? key < o.key : observer < o.observer; }
};
DueKey g_due_idx[kDueCapacity];

// Under g_mu: the sorted index of every withheld (key, observer).
size_t build_held_index_locked() {
    size_t n = 0;
    auto add = [&](const auto& t) {
        for (size_t i = 0; i < t.size() && n < kHeldIndexCapacity; ++i) g_held_idx[n++] = {t.at(i).key, t.at(i).observer};
    };
    add(g_npc_table);
    add(g_fam_table);
    add(g_table);
    add(g_settle_table);
    std::sort(g_held_idx, g_held_idx + n);
    return n;
}

bool held_in_index(size_t n, uint32_t key, uintptr_t observer) {
    return std::binary_search(g_held_idx, g_held_idx + n, HeldKey{key, observer});
}

struct ObserverInfo {
    uintptr_t session = 0, user = 0;
    uint32_t key = 0;
    bool valid = false;
};

// observer_hold_family: the depth of each release (0 = its parent is not in this batch for that observer; else
// its parent's + 1). A few rounds: a deeper chain keeps the depth it reached (its parent is still sorted first
// whenever their depths differ).
void due_depths(NpcDue* due, size_t n) {
    for (size_t i = 0; i < n; ++i) g_due_idx[i] = {due[i].key, due[i].observer, static_cast<uint32_t>(i)};
    std::sort(g_due_idx, g_due_idx + n);
    for (int round = 0; round < 8; ++round) {
        bool changed = false;
        for (size_t i = 0; i < n; ++i) {
            if (!due[i].parent) continue;
            const DueKey probe{due[i].parent, due[i].observer, 0};
            const DueKey* it = std::lower_bound(g_due_idx, g_due_idx + n, probe);
            if (it == g_due_idx + n || it->key != probe.key || it->observer != probe.observer) continue;
            const uint8_t d = static_cast<uint8_t>(std::min<int>(due[it->at].depth + 1, 64));
            if (d > due[i].depth) {
                due[i].depth = d;
                changed = true;
            }
        }
        if (!changed) break;
    }
}

// observer_hold_family: the counters and the line of one member's release (a converted observer_hold entry
// counts as an NPC release too).
void count_family_release(const NpcDue& d, uintptr_t session, const char* where, size_t nkeys) {
    g_fm_released.fetch_add(1);
    switch (d.fkind) {
        case FamilyRelease::WithParent: g_fm_with_parent.fetch_add(1); break;
        case FamilyRelease::AfterParent: g_fm_after_parent.fetch_add(1); break;
        case FamilyRelease::Orphan: g_fm_orphans.fetch_add(1); break;
        case FamilyRelease::OrphanTimeout: {
            const uint64_t to = g_fm_orphan_timeouts.fetch_add(1) + 1;
            const uint64_t waited = g_fm_held_unknown.load() + g_fm_converted.load();
            if (to >= kFamUnknownValveMin && to * kFamUnknownValveDiv > waited &&
                !g_fm_unknown_off.exchange(true)) {
                note(g_fm_valve_logged, 1, kNoteFamOther, {11, to, waited});
            }
            break;
        }
        case FamilyRelease::MaxAge: g_fm_max_age.fetch_add(1); break;
        default: break;
    }
    store_max(g_fm_age_max, d.age_ms);
    note(g_fm_rel_logged, kMaxFamRelLogged, kNoteFamReleased,
         {d.key, d.type, d.parent, session, static_cast<uint64_t>(d.observer_host), d.age_ms,
          static_cast<uint64_t>(d.fkind), ptr_bits(where), nkeys, d.depth});
    if (d.npc_origin) {
        g_npc_released.fetch_add(1);
        g_npc_age_sum.fetch_add(d.age_ms);
        store_max(g_npc_age_max, d.age_ms);
        if (d.defer) {
            g_ld_released.fetch_add(1);
            g_ld_wait_sum.fetch_add(d.age_ms);
            store_max(g_ld_wait_max, d.age_ms);
        }
    }
}

// observer_hold: the releases, one native NotifyAppear per observer session
// (all its due keys in one 2005, as the engine itself batches them). Stable:
// per observer, parents first (observer_hold_family's depth), else in the order they were decided.
void release_npcs(NpcDue* due, size_t n, const char* where) {
    due_depths(due, n);
    std::stable_sort(due, due + n, [](const NpcDue& a, const NpcDue& b) {
        if (a.observer != b.observer) return a.observer < b.observer;
        return a.depth < b.depth;
    });
    const uintptr_t live = g_family.load(std::memory_order_relaxed) ? server_live_session2() : 0;
    for (size_t i = 0; i < n;) {
        size_t j = i;
        size_t nk = 0;
        while (j < n && due[j].observer == due[i].observer) g_due_keys[nk++] = due[j++].key;
        const uintptr_t session = due[i].observer;
        const GameVec s{&session, 1, 1};
        const GameVec k{g_due_keys, static_cast<uint32_t>(nk), static_cast<uint32_t>(nk)};
        call_notify(0, &s, &k);  // the engine's own call: a fresh 2005, serialised now
        g_npc_release_calls.fetch_add(1);
        // observer_hold_family: user 2 has these now.
        if (live && session == live) {
            std::lock_guard lock(g_mu);
            known_sync_locked(live, server_epoch());
            known_add_locked(std::span<const uint32_t>(g_due_keys, nk));
        }
        // observer_hold_acks: a key whose 2005 did not reach take_frame during that call waits a little more.
        if (const uintptr_t acks = ack_session(); acks && session == acks) {
            observer_hold_acks_released(std::span<const uint32_t>(g_due_keys, nk));
        }
        for (size_t x = i; x < j; ++x) {
            const NpcDue& d = due[x];
            if (d.family) {
                count_family_release(d, session, where, j - i);
                continue;
            }
            g_npc_released.fetch_add(1);
            if (d.kind == NpcRelease::ByControl) g_npc_released_ctrl.fetch_add(1);
            if (d.kind == NpcRelease::Timeout) {
                g_npc_timeouts.fetch_add(1);
                // Must stay 0 (npc_release_step withholds them): to the host, with restore 0, user 2 its controller.
                const uint32_t u2 = server_user2_user_key();
                if (d.observer_host && u2 && d.controller == u2) g_npc_timeout_host_u2.fetch_add(1);
            }
            if (d.kind == NpcRelease::Native) g_npc_native.fetch_add(1);
            g_npc_age_sum.fetch_add(d.age_ms);
            store_max(g_npc_age_max, d.age_ms);
            if (d.defer) {
                // observer_load_defer: its own counters and lines (the release budget stays for restore 0).
                g_ld_released.fetch_add(1);
                if (d.at_cap) g_ld_cap.fetch_add(1);
                g_ld_wait_sum.fetch_add(d.age_ms);
                store_max(g_ld_wait_max, d.age_ms);
                note(g_ld_rel_logged, hold::kLoadDeferLogged, kNoteLoadReleased,
                     {d.key, d.type, session, d.age_ms, static_cast<uint64_t>(d.at_cap), ptr_bits(where), j - i});
                continue;
            }
            note(g_npc_release_logged, kMaxNpcReleaseLogged, kNoteNpcReleased,
                 {d.key, d.type, d.controller, session, static_cast<uint64_t>(d.observer_host), d.observer_key, d.age_ms,
                  static_cast<uint64_t>(d.kind), ptr_bits(where), j - i, ptr_bits(d.why)});
        }
        i = j;
    }
}

// observer_hold_family: the parents whose family follows them now (released behind, or dropped with them),
// sorted by (key, observer): one walk of the family table per level, whatever their number (review 5). Two
// static frontiers (one pass at a time: g_npc_busy).
struct Root {
    uint32_t key = 0;
    uintptr_t observer = 0;
    uint32_t observer_key = 0;
    uint8_t depth = 0;
    bool operator<(const Root& o) const { return key != o.key ? key < o.key : observer < o.observer; }
};
Root g_roots_a[kDueCapacity], g_roots_b[kDueCapacity];
// The drops of one pass (NPC entries and family entries on their own) whose family goes with them.
Root g_drop_roots[kDueCapacity];

// Under g_mu: the family entries behind g_roots_a[0..n) leave the table, level by level: released into g_due
// (depth + 1; `kind` for the first level, WithParent below) or dropped into g_pgone (noted after the lock).
void take_family_levels_locked(size_t n, bool release, uint64_t now, size_t& n_due, size_t& n_gone,
                               FamilyRelease kind = FamilyRelease::WithParent) {
    Root* cur = g_roots_a;
    Root* next = g_roots_b;
    for (int level = 0; n && g_fam_table.size() && level < 64; ++level) {
        std::sort(cur, cur + n);
        size_t m = 0;
        for (size_t i = 0; i < g_fam_table.size();) {
            const HoldEntry& pe = g_fam_table.at(i);
            Root probe;
            probe.key = pe.parent;
            probe.observer = pe.observer;
            const Root* it = std::lower_bound(cur, cur + n, probe);
            if (it == cur + n || it->key != pe.parent || it->observer != pe.observer) {
                ++i;
                continue;
            }
            const uint8_t depth = static_cast<uint8_t>(std::min<int>(it->depth + 1, 64));
            const uint64_t age = now >= pe.since_ms ? now - pe.since_ms : 0;
            if (release && n_due < kDueCapacity) {
                NpcDue d{pe.key, pe.observer, it->observer_key, age, pe.type, pe.observer_host, pe.controller,
                         NpcRelease::None, "", pe.defer, false};
                d.family = true;
                d.parent = pe.parent;
                d.fkind = kind;
                d.npc_origin = pe.npc_origin;
                d.depth = depth;
                d.src = pe;
                g_due[n_due++] = d;
            } else if (n_gone < hold::kFamilyTableCapacity) {
                g_pgone[n_gone++] = pe;
            }
            if (m < kDueCapacity) next[m++] = {pe.key, pe.observer, it->observer_key, depth};
            g_fam_table.remove_at(i);  // the last entry moves here: looked at next
        }
        std::swap(cur, next);
        n = m;
        kind = FamilyRelease::WithParent;
    }
}

// observer_hold_family: a member released with its parent goes only while it still exists (by key; unreadable:
// it goes, NotifyAppear looks it up itself). Returns the new n_due.
size_t drop_despawned_members(uintptr_t sam, size_t n_due, uintptr_t acks) {
    const game::FastReads m;
    size_t w = 0;
    for (size_t x = 0; x < n_due; ++x) {
        const NpcDue& d = g_due[x];
        if (d.family && (d.fkind == FamilyRelease::WithParent || d.fkind == FamilyRelease::AfterParent)) {
            const auto actor = find_actor_with(m, sam, d.key);
            if (actor && !*actor) {
                g_fm_dropped.fetch_add(1);
                note(g_fm_other_logged, kMaxFamOtherLogged, kNoteFamOther, {6, d.key, d.parent, d.observer});
                if (acks && d.observer == acks) observer_hold_acks_drop(d.key);
                continue;
            }
        }
        g_due[w++] = d;
    }
    return w;
}

// S35 publication_gate (publication_gate_logic.h; AUDITORIA.md §1 "Cambios obligatorios"): EVERY release of a
// batch (g_due[0..n): observer_hold's Restore1 / ByControl / Timeout / Native, the family's WithParent / AfterParent
// / Orphan / OrphanTimeout / MaxAge, "no room: released anyway") is admitted or refused here, right before
// release_npcs, outside g_mu, with protected SEH reads by key: the actor, its controller, its CC (three states) and
// its parent (withheld, refused in this batch, or its own state). Parents are decided first (depth), so the members
// of a refused parent are refused too. Refused with the key at 1: put back into its table (retained, decided again
// after pubg::kRetryMs) or, past publication_retain_max_ms from its first refusal or without room, dropped WITHOUT
// being published. probe: counted and logged, published exactly as before. One pass at a time (g_npc_busy).
//
// Revisión S35: dos fases (10): primero cada liberación por su propio estado y el de su padre leído; después la
// propagación «padre rechazado en este lote» por el vínculo LEÍDO (no sólo por la profundidad serializada) hasta un
// punto fijo, así un hijo nunca sale antes que un padre rechazado por una dependencia de segundo nivel. La regla del
// controlador es una (9): quien lo controla lo recibe siempre. Devolver una entrada que ya se retuvo de nuevo con un
// anuncio fresco sólo fusiona su retención (6). Soltar un padre sin publicar arrastra a sus miembros (7).
struct PubRead {
    pubg::Facts f;
    pubg::ParentFacts pf;
    uint32_t parent = 0;
    bool has_link = false;
};
// The protected reads of one release (or of a probe shadow record): the actor, its controller, its CC and its parent's.
PubRead pub_read(const game::FastReads& m, uintptr_t sam, uint32_t key, uint32_t observer_key, uint32_t host_key,
                 uint32_t user2_key) {
    PubRead r;
    r.f.actor = find_actor_with(m, sam, key);
    r.f.observer_key = observer_key;
    r.f.host_key = host_key;
    r.f.user2_key = user2_key;
    if (!r.f.actor || !*r.f.actor) return r;
    r.f.controller = m.rd<uint32_t>(*r.f.actor + hold::kActorController);
    r.f.cc = cc_state_with(m, *r.f.actor);
    const auto link = family_parent_with(m, *r.f.actor, key, piece_parent_with(m, *r.f.actor));
    r.has_link = link.has_value();
    r.parent = link.value_or(0) == key ? 0 : link.value_or(0);
    if (r.has_link && r.parent) {
        r.pf.actor = find_actor_with(m, sam, r.parent);
        if (r.pf.actor && *r.pf.actor) {
            r.pf.controller = m.rd<uint32_t>(*r.pf.actor + hold::kActorController);
            r.pf.cc = cc_state_with(m, *r.pf.actor);
        }
    }
    return r;
}
pubg::Verdict pub_verdict(PubRead& r) {
    if (r.f.actor && *r.f.actor) {
        r.f.dep = pubg::parent_dep(r.has_link, r.parent, r.pf, r.f.observer_key, r.f.host_key, r.f.user2_key);
    }
    return pubg::admit(r.f);
}
void pub_users(uint32_t& host_key, uint32_t& user2_key) {
    uintptr_t host = 0, user2 = 0;
    host_key = host_key_now(host);
    user2_key = server_user2(user2) && user2 ? user_key_fast(user2) : 0;
}
struct PubBack {
    NpcDue due;
    pubg::Verdict verdict;
    uint8_t drop = 0;  // 0 retained, 1 dropped (retention over), 2 dropped (no room), 3 gone
};
PubBack g_pub_back[kDueCapacity];
PubRead g_pub_read[kDueCapacity];
pubg::Verdict g_pub_verdict[kDueCapacity];
struct PubIdx {
    uint32_t key;
    uintptr_t observer;
    uint32_t at;
    bool operator<(const PubIdx& o) const { return key != o.key ? key < o.key : observer < o.observer; }
};
PubIdx g_pub_idx[kDueCapacity];
// probe (4): what WOULD have been retained, followed by later passes until it would have recovered (admissible) or
// its retention would have run out. Bounded; only under g_npc_busy (gate_releases and npc_pass).
struct PubShadow {
    uint32_t key = 0;
    uintptr_t observer = 0;
    uint32_t observer_key = 0;
    uint64_t since_ms = 0;
};
constexpr size_t kPubShadow = 256;
PubShadow g_pub_shadow[kPubShadow];
size_t g_pub_shadow_n = 0;  // under g_npc_busy
void pub_shadow_add(const NpcDue& d, uint64_t now) {
    for (size_t i = 0; i < g_pub_shadow_n; ++i) {
        if (g_pub_shadow[i].key == d.key && g_pub_shadow[i].observer == d.observer) return;  // its first moment stays
    }
    if (g_pub_shadow_n >= kPubShadow) {
        g_pg_shadow_full.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    g_pub_shadow[g_pub_shadow_n++] = {d.key, d.observer, d.observer_key, now};
    g_pg_shadow_recorded.fetch_add(1, std::memory_order_relaxed);
    g_pub_shadow_size.store(g_pub_shadow_n, std::memory_order_relaxed);
}
// Under g_npc_busy, after a pass (probe only): up to 64 records read again.
void pub_shadow_sweep(uintptr_t sam, uint64_t now) {
    if (pub_gate() != pubg::Mode::Probe || !g_pub_shadow_n) return;
    uint32_t hk = 0, uk = 0;
    pub_users(hk, uk);
    const game::FastReads m;
    const uint64_t retain_ms = g_pub_retain_ms.load(std::memory_order_relaxed);
    for (size_t i = 0, seen = 0; i < g_pub_shadow_n && seen < 64; ++seen) {
        const PubShadow s = g_pub_shadow[i];
        PubRead r = pub_read(m, sam, s.key, s.observer_key, hk, uk);
        const pubg::Verdict v = pub_verdict(r);
        const uint64_t age = now >= s.since_ms ? now - s.since_ms : 0;
        bool done = true;
        if (v == pubg::Verdict::Publish && age < retain_ms) {
            g_pg_shadow_recovered.fetch_add(1, std::memory_order_relaxed);
            store_max(g_pg_shadow_recover_max_ms, age);
        } else if (v == pubg::Verdict::Gone) {
            g_pg_shadow_gone.fetch_add(1, std::memory_order_relaxed);
        } else if (age >= retain_ms) {
            g_pg_shadow_would_drop.fetch_add(1, std::memory_order_relaxed);
        } else {
            done = false;
        }
        if (done) {
            g_pub_shadow[i] = g_pub_shadow[--g_pub_shadow_n];
        } else {
            ++i;
        }
    }
    g_pub_shadow_size.store(g_pub_shadow_n, std::memory_order_relaxed);
}
size_t gate_releases(uintptr_t sam, size_t n_due, uint64_t now, const char* where) {
    const pubg::Mode gate = pub_gate();
    if (gate == pubg::Mode::Off || !n_due) return n_due;
    due_depths(g_due, n_due);
    std::stable_sort(g_due, g_due + n_due, [](const NpcDue& a, const NpcDue& b) {
        if (a.observer != b.observer) return a.observer < b.observer;
        return a.depth < b.depth;
    });
    size_t n_idx = 0;
    {
        std::lock_guard lock(g_mu);
        n_idx = build_held_index_locked();
    }
    uint32_t hk = 0, uk = 0;
    pub_users(hk, uk);
    const game::FastReads m;
    // 1. Each release by its own state and its read parent's (withheld from that observer, or incomplete).
    for (size_t x = 0; x < n_due; ++x) {
        const NpcDue& d = g_due[x];
        g_pub_read[x] = pub_read(m, sam, d.key, d.observer_key, hk, uk);
        PubRead& r = g_pub_read[x];
        if (r.has_link && r.parent) r.pf.withheld = held_in_index(n_idx, r.parent, d.observer);
        g_pub_verdict[x] = pub_verdict(r);
        g_pub_idx[x] = {d.key, d.observer, static_cast<uint32_t>(x)};
    }
    // 2. A parent refused in this batch (by the read link, any order, any depth) refuses its children: a fixed point.
    std::sort(g_pub_idx, g_pub_idx + n_due);
    for (int round = 0; round < 64; ++round) {
        bool changed = false;
        for (size_t x = 0; x < n_due; ++x) {
            PubRead& r = g_pub_read[x];
            if (!r.has_link || !r.parent || r.pf.in_batch) continue;
            if (g_pub_verdict[x] != pubg::Verdict::Publish && g_pub_verdict[x] != pubg::Verdict::Dependency) continue;
            const PubIdx probe{r.parent, g_due[x].observer, 0};
            const PubIdx* it = std::lower_bound(g_pub_idx, g_pub_idx + n_due, probe);
            if (it == g_pub_idx + n_due || it->key != probe.key || it->observer != probe.observer) continue;
            if (!pubg::retained(g_pub_verdict[it->at])) continue;
            r.pf.in_batch = true;
            const pubg::Verdict v = pub_verdict(r);
            if (v != g_pub_verdict[x]) {
                g_pub_verdict[x] = v;
                changed = true;
            }
        }
        if (!changed) break;
    }
    // 3. Publish, drop the gone, count / log, put back.
    size_t n_back = 0, w = 0;
    const uintptr_t acks = ack_session();
    for (size_t x = 0; x < n_due; ++x) {
        const NpcDue d = g_due[x];
        const pubg::Verdict v = g_pub_verdict[x];
        const uint32_t parent = g_pub_read[x].parent;
        const uintptr_t slot = g_pub_read[x].f.cc.slot;
        g_pg_evaluated.fetch_add(1, std::memory_order_relaxed);
        if (v == pubg::Verdict::Publish) {
            g_pg_published.fetch_add(1, std::memory_order_relaxed);
            g_due[w++] = d;
            continue;
        }
        if (v == pubg::Verdict::Gone) {
            // Not in the SAM any more: nothing to announce; what was kept for it goes, and its members with it.
            g_pg_gone.fetch_add(1, std::memory_order_relaxed);
            if (gate == pubg::Mode::Probe) {
                g_due[w++] = d;
            } else {
                if (acks && d.observer == acks) observer_hold_acks_drop(d.key);
                g_pub_back[n_back++] = {d, v, 3};
            }
            continue;
        }
        g_pg_by_verdict[static_cast<size_t>(v)].fetch_add(1, std::memory_order_relaxed);
        if (gate == pubg::Mode::Probe) {
            g_pg_would.fetch_add(1, std::memory_order_relaxed);
            note(g_pg_logged, kMaxPubLogged, kNotePubRefused,
                 {d.key, d.type, d.observer, static_cast<uint64_t>(d.observer_host), static_cast<uint64_t>(v), parent, 1,
                  ptr_bits(d.family ? family_release_name(d.fkind) : npc_release_name(d.kind)), d.age_ms, slot});
            pub_shadow_add(d, now);
            g_due[w++] = d;
            continue;
        }
        if (!d.src.unsafe_since_ms) {
            note(g_pg_logged, kMaxPubLogged, kNotePubRefused,
                 {d.key, d.type, d.observer, static_cast<uint64_t>(d.observer_host), static_cast<uint64_t>(v), parent, 0,
                  ptr_bits(d.family ? family_release_name(d.fkind) : npc_release_name(d.kind)), d.age_ms, slot});
        }
        g_pub_back[n_back++] = {d, v, 0};
    }
    if (!n_back) return w;
    // Back into their tables (retained), merged with a fresh hold of the same (key, observer), or dropped without
    // publishing; the members of whatever is dropped (or gone) go with it. Under the lock; the lines after it.
    size_t n_drop = 0, n_roots = 0, n_gone = 0;
    {
        std::lock_guard lock(g_mu);
        const uint64_t retain_ms = g_pub_retain_ms.load(std::memory_order_relaxed);
        for (size_t i = 0; i < n_back; ++i) {
            PubBack& b = g_pub_back[i];
            if (b.drop == 3) {
                if (n_roots < kDueCapacity) g_roots_a[n_roots++] = {b.due.key, b.due.observer, 0, 0};
                continue;
            }
            HoldEntry e = b.due.src;
            const uint64_t since = e.unsafe_since_ms ? e.unsafe_since_ms : now;
            const auto put = [&](auto& table, size_t reserved) {
                if (HoldEntry* fresh = table.find(e.key, e.observer)) {
                    // A fresh hold of the same key arrived meanwhile: its fields stay; only the retention merges (the
                    // oldest refusal, the latest retry). Not a retention of ours: the next pass decides it (and drops it
                    // if the merged retention is over).
                    fresh->unsafe_since_ms = fresh->unsafe_since_ms ? std::min(fresh->unsafe_since_ms, since) : since;
                    fresh->unsafe_retry_ms = std::max(fresh->unsafe_retry_ms, now + pubg::kRetryMs);
                    fresh->unsafe_why = static_cast<uint8_t>(b.verdict);
                    g_pg_merged.fetch_add(1, std::memory_order_relaxed);
                    return true;
                }
                // The room promised to splits not recorded yet is not ours to take.
                const bool room = table.room() > std::min(table.room(), reserved);
                const pubg::Retention r = pubg::retention(since, now, retain_ms, room);
                if (r != pubg::Retention::Retain) {
                    b.drop = r == pubg::Retention::DropExpired ? 1 : 2;
                    return false;
                }
                e.unsafe_since_ms = since;
                e.unsafe_retry_ms = now + pubg::kRetryMs;
                e.unsafe_why = static_cast<uint8_t>(b.verdict);
                using Table = std::remove_reference_t<decltype(table)>;
                if (table.add(e) == Table::Add::Full) {
                    b.drop = 2;
                    return false;
                }
                g_pg_retained.fetch_add(1, std::memory_order_relaxed);
                return true;
            };
            const bool kept = b.due.family ? put(g_fam_table, g_fam_reserved) : put(g_npc_table, g_npc_reserved);
            store_max(g_pg_retain_max_ms, now >= since ? now - since : 0);
            if (kept) continue;
            (b.drop == 1 ? g_pg_dropped_expired : g_pg_dropped_no_room).fetch_add(1, std::memory_order_relaxed);
            b.due.src.unsafe_since_ms = since;
            if (n_roots < kDueCapacity) g_roots_a[n_roots++] = {b.due.key, b.due.observer, 0, 0};
            g_pub_back[n_drop++] = b;
        }
        if (n_roots && g_fam_table.size()) {
            size_t no_due = 0;
            take_family_levels_locked(n_roots, false, now, no_due, n_gone);
        }
        g_npc_size.store(g_npc_table.size());
        g_fam_size.store(g_fam_table.size());
    }
    for (size_t i = 0; i < n_drop; ++i) {
        const PubBack& b = g_pub_back[i];
        note(g_pg_drop_logged, kMaxPubDropLogged, kNotePubDropped,
             {b.due.key, b.due.type, b.due.observer, static_cast<uint64_t>(b.due.observer_host),
              static_cast<uint64_t>(b.verdict), now >= b.due.src.unsafe_since_ms ? now - b.due.src.unsafe_since_ms : 0,
              static_cast<uint64_t>(b.drop == 2)});
        if (acks && b.due.observer == acks) observer_hold_acks_drop(b.due.key);
    }
    for (size_t k = 0; k < n_gone; ++k) {
        const HoldEntry& pe = g_pgone[k];
        g_pg_members_dragged.fetch_add(1, std::memory_order_relaxed);
        g_fm_dropped.fetch_add(1);
        note(g_fm_other_logged, kMaxFamOtherLogged, kNoteFamDropped,
             {pe.key, pe.parent, pe.observer, static_cast<uint64_t>(pe.observer_host),
              now >= pe.since_ms ? now - pe.since_ms : 0, ptr_bits("its parent was dropped unpublished")});
        if (acks && pe.observer == acks) observer_hold_acks_drop(pe.key);
    }
    (void)where;
    return w;
}

// observer_hold_family: `keys` were just announced to `sessions` by the engine's own NotifyAppear (or a split's
// pass / groups). With user 2's live session 2 among them they join its announced set, and (key at 1, a thread
// that may call NotifyAppear, no pass running) the members waiting there behind one of them go now, right after
// it: one more NotifyAppear to that session, parents first. Otherwise the next pass releases them.
void family_delivered(std::span<const uint32_t> keys, std::span<const uintptr_t> sessions, bool allow_release,
                      const char* where) {
    const uint8_t mode = g_family.load(std::memory_order_relaxed);
    if (!mode || !g_observers.load(std::memory_order_relaxed) || keys.empty()) return;
    const uintptr_t s2 = server_live_session2();
    if (!s2 || std::find(sessions.begin(), sessions.end(), s2) == sessions.end()) return;
    const uint32_t epoch = server_epoch();
    const bool want = allow_release && mode >= 2 && g_fam_size.load(std::memory_order_relaxed) != 0;
    const bool busy = want && g_npc_busy.test_and_set(std::memory_order_acquire);
    const bool release = want && !busy;
    struct Clear {
        bool on;
        ~Clear() {
            if (on) g_npc_busy.clear(std::memory_order_release);
        }
    } clear{release};
    size_t n_due = 0, n_gone = 0;
    const uint64_t now = now_ms();
    {
        std::lock_guard lock(g_mu);
        known_sync_locked(s2, epoch);
        known_add_locked(keys);
        if (release && g_fam_table.size()) {
            // What waits behind them there, and the members of those (behind, in the same call).
            size_t n = 0;
            for (const uint32_t k : keys) {
                if (n < kDueCapacity) g_roots_a[n++] = {k, s2, 0, 0};
            }
            take_family_levels_locked(n, true, now, n_due, n_gone, FamilyRelease::AfterParent);
            g_fam_size.store(g_fam_table.size());
        }
    }
    if (!n_due) return;
    const auto sam = sam_now(true);
    if (sam) n_due = drop_despawned_members(*sam, n_due, ack_session());
    if (!n_due) return;
    const uint32_t obs_key = [&] {
        uintptr_t u = 0;
        return server_session_user(s2, u) ? user_key_fast(u) : 0u;
    }();
    for (size_t x = 0; x < n_due; ++x) g_due[x].observer_key = obs_key;
    // S35 publication_gate: the members that follow their parent are admitted like any other release (unreadable
    // SAM: every one refused, never published blind).
    n_due = gate_releases(sam ? *sam : 0, n_due, now, where);
    if (!n_due) return;
    g_fm_tail_calls.fetch_add(1, std::memory_order_relaxed);
    release_npcs(g_due, n_due, where);
}

// target != 0: only the entries of that actor key (after its StartActionReq);
// target == 0: the next kNpcPassBudget entries, round robin, and (observer_hold_family) the whole family table.
// allow_release = false (the receiving thread): a release is left for the next pass that may
// call NotifyAppear (counted as deferred); drops and notes happen here.
void npc_pass(uint32_t target, bool allow_release, const char* where) {
    if (!g_npc_size.load(std::memory_order_relaxed) && !g_fam_size.load(std::memory_order_relaxed)) return;
    if (g_npc_busy.test_and_set(std::memory_order_acquire)) {
        g_npc_busy_skips.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    struct Busy {
        ~Busy() { g_npc_busy.clear(std::memory_order_release); }
    } busy;
    const uint64_t t0 = qpc_us();
    (target ? g_npc_targeted : g_npc_periodic).fetch_add(1, std::memory_order_relaxed);
    if (!target) {
        // User 2 left or is leaving: what it observes goes (the network tick does it too).
        uintptr_t user2 = 0;
        const bool present = server_user2(user2);
        if (hold_drop_user2(present, server_logout_handed())) {
            std::lock_guard lock(g_mu);
            if (!drop_npc_user2_locked(present)) return;
        }
    }
    const auto sam = sam_now(true);
    if (!sam) return;
    const uint64_t now = now_ms();
    const uint32_t epoch = server_epoch();
    // observer_hold_family: user 2's session, whose announced set the decisions read.
    const uint8_t fam_mode = g_family.load(std::memory_order_relaxed);
    const uintptr_t live = fam_mode ? server_live_session2() : 0;
    // 1. Copy the entries to decide on (under the lock, nothing else).
    size_t n = 0, n_p = 0;
    {
        std::lock_guard lock(g_mu);
        if (live) known_sync_locked(live, epoch);
        const size_t size = g_npc_table.size();
        if (target) {
            for (size_t i = 0; i < size && n < hold::kNpcPassBudget; ++i) {
                if (g_npc_table.at(i).key == target) g_snap[n++] = {g_npc_table.at(i), i};
            }
        } else if (size) {
            const size_t start = g_npc_cursor % size;
            const size_t count = std::min(size, hold::kNpcPassBudget);
            for (size_t j = 0; j < count; ++j) {
                const size_t i = (start + j) % size;
                g_snap[n++] = {g_npc_table.at(i), i};
            }
            g_npc_cursor = start + count;
        }
        // observer_hold_family: the periodic passes look at every member (its parent, max wait, epoch).
        if (!target && g_fam_table.size()) {
            const size_t n_idx = build_held_index_locked();
            for (size_t i = 0; i < g_fam_table.size() && n_p < hold::kFamilyTableCapacity; ++i) {
                FamSnap& ps = g_psnap[n_p++];
                ps = FamSnap{};
                ps.e = g_fam_table.at(i);
                ps.index = i;
                ps.parent_held = held_in_index(n_idx, ps.e.parent, ps.e.observer);
                ps.tracks = live && ps.e.observer == live && g_known_session == live;
                ps.parent_known = ps.tracks && g_known.contains(ps.e.parent);
            }
        }
    }
    if (!n && !n_p) return;
    if (allow_release) g_defer.ran(now);
    g_npc_evaluated.fetch_add(n, std::memory_order_relaxed);
    // 2. Decide outside the lock: SEH reads by key, one validation per observer session.
    ObserverInfo obs[8];
    size_t n_obs = 0;
    auto observer_info = [&](uintptr_t session) {
        for (size_t o = 0; o < n_obs; ++o) {
            if (obs[o].session == session) return obs[o];
        }
        ObserverInfo oi;
        oi.session = session;
        oi.valid = server_session_user(session, oi.user);
        oi.key = oi.valid ? user_key_fast(oi.user) : 0;
        if (n_obs < std::size(obs)) obs[n_obs++] = oi;
        return oi;
    };
    const game::FastReads m;
    const bool children = g_children.load(std::memory_order_relaxed);
    // observer_load_defer=1: user 2 is loading now (one reading per pass).
    const bool load_gate = g_load_defer.load(std::memory_order_relaxed) >= 2 && user2_loading_now(now);
    // A release while user 2 still has no 2762 (the entry's 60 s, or a load taken as finished): "at the cap".
    const bool no_2762_yet = g_user2_loading.load(std::memory_order_relaxed);
    uintptr_t user2_now = 0;
    const bool user2_present = server_user2(user2_now) && user2_now != 0 && !server_logout_handed();
    const uint64_t load_end =
        g_load_defer.load(std::memory_order_relaxed) >= 2 ? g_load_end_ms.load(std::memory_order_relaxed) : 0;
    // S35 publication_gate, review 8: the retention bound is checked on EVERY pass (not only when a release is refused
    // again) and the longest retention is measured on every retained entry.
    const uint64_t retain_ms = g_pub_retain_ms.load(std::memory_order_relaxed);
    const char* const kRetentionOver = "publication gate: retention over, dropped unpublished";
    const auto retention_over = [&](const HoldEntry& e) {
        if (!e.unsafe_since_ms || now < e.unsafe_since_ms) return false;
        store_max(g_pg_retain_max_ms, now - e.unsafe_since_ms);
        return now - e.unsafe_since_ms >= retain_ms;
    };
    const auto note_over = [&](const HoldEntry& e) {
        g_pg_dropped_expired.fetch_add(1, std::memory_order_relaxed);
        note(g_pg_drop_logged, kMaxPubDropLogged, kNotePubDropped,
             {e.key, e.type, e.observer, static_cast<uint64_t>(e.observer_host), e.unsafe_why, now - e.unsafe_since_ms,
              0});
    };
    for (size_t k = 0; k < n; ++k) {
        const HoldEntry& e = g_snap[k].e;
        if (retention_over(e)) {
            NpcDecision& d = g_dec[k];
            d = NpcDecision{};
            d.step = ReleaseStep::Drop;  // its family goes with it (step 3), its kept packets too (step 4)
            d.why = kRetentionOver;
            d.age = now >= e.since_ms ? now - e.since_ms : 0;
            g_order[k] = static_cast<uint16_t>(k);
            note_over(e);
            continue;
        }
        // S35 publication_gate: an entry the gate just refused waits pubg::kRetryMs before it is decided again.
        if (e.unsafe_retry_ms && now < e.unsafe_retry_ms) {
            g_dec[k] = NpcDecision{};
            g_order[k] = static_cast<uint16_t>(k);
            continue;
        }
        const ObserverInfo oi = observer_info(e.observer);
        NpcReleaseReadings r = read_npc_release(*sam, e.key, e.observer_user);
        r.epoch_now = epoch;
        r.observer_valid = oi.valid;
        r.observer_user = oi.user;
        r.observer_key = oi.key;
        r.load_wait = load_gate && !e.observer_host;
        r.user2_key = server_user2_user_key();
        NpcDecision& d = g_dec[k];
        d = NpcDecision{};
        d.age = now >= e.since_ms ? now - e.since_ms : 0;
        // Review L2: an entry held through user 2's load gets its whole restore-0 timeout after the load.
        if (load_end && load_end > e.since_ms && !e.observer_host) r.timeout_age_ms = now >= load_end ? now - load_end : 0;
        d.step = npc_release_step(e, r, d.age, d.why, &d.kind, children);
        if (d.step == ReleaseStep::Keep && r.load_wait && d.age < hold::kLoadDeferMaxMs) {
            g_ld_kept.fetch_add(1, std::memory_order_relaxed);
        }
        d.observer_key = r.observer_key;
        d.controller_now = r.controller.value_or(0);
        if (d.step == ReleaseStep::Release && !allow_release) {
            d.step = ReleaseStep::Keep;  // released by the next pass on a thread that may call NotifyAppear
            g_npc_deferred.fetch_add(1, std::memory_order_relaxed);
            g_defer.deferred(now, cur_tid(), hold::DeferWatch::kNpc);
        }
        // observer_hold_family: a release to user 2's session reads its parent (gated under the lock below).
        if (d.step == ReleaseStep::Release && live && e.observer == live && r.actor && *r.actor) {
            d.parent = family_parent_with(m, *r.actor, e.key, piece_parent_with(m, *r.actor)).value_or(0);
            if (d.parent == e.key) d.parent = 0;
        }
        if (d.step == ReleaseStep::Keep) {
            d.note_ctrl = r.controller && *r.controller != e.controller && !e.ctrl_change_noted;
            // A wait for user 2's 2762 (observer_load_defer) is not "slow": no line for it.
            d.note_slow = !e.timeout_noted && d.age >= hold::kTimeoutMs && !r.load_wait;
            d.note_u2 = d.kind == NpcRelease::WithheldUser2 && !e.u2_withheld_noted;
        }
        g_order[k] = static_cast<uint16_t>(k);
    }
    // 2b. observer_hold_family: the members on their own (family_release_step).
    for (size_t k = 0; k < n_p; ++k) {
        FamSnap& ps = g_psnap[k];
        if (retention_over(ps.e)) {
            ps.step = ReleaseStep::Drop;
            ps.why = kRetentionOver;
            ps.age = now >= ps.e.since_ms ? now - ps.e.since_ms : 0;
            note_over(ps.e);
            continue;
        }
        if (ps.e.unsafe_retry_ms && now < ps.e.unsafe_retry_ms) continue;  // S35: refused just now (Keep)
        const ObserverInfo oi = observer_info(ps.e.observer);
        FamilyReadings r;
        r.epoch_now = epoch;
        r.actor = find_actor_with(m, *sam, ps.e.key);
        r.observer_valid = oi.valid;
        r.observer_user = oi.user;
        r.parent_held = ps.parent_held;
        r.tracks = ps.tracks;
        r.parent_known = ps.parent_known;
        if (r.actor && *r.actor) {
            if (const auto sector = sector_with(m, *r.actor)) r.observes = observed_by_with(m, *sector, ps.e.observer_user);
        }
        ps.age = now >= ps.e.since_ms ? now - ps.e.since_ms : 0;
        const uint64_t ws = ps.e.wait_since_ms ? ps.e.wait_since_ms : ps.e.since_ms;
        ps.wait = now >= ws ? now - ws : 0;
        ps.observer_key = oi.key;
        ps.step = family_release_step(ps.e, r, ps.age, ps.wait, ps.why, &ps.kind);
        if (ps.step == ReleaseStep::Release && !allow_release) {
            ps.step = ReleaseStep::Keep;  // released by the next pass on a thread that may call NotifyAppear
            g_fm_deferred.fetch_add(1, std::memory_order_relaxed);
            g_defer.deferred(now, cur_tid(), hold::DeferWatch::kNpc);
        }
    }
    // 3. Re-lock only to apply: the entries still there and unchanged (stamp),
    //    highest index first (a removal moves the last entry into its place).
    //    A released NPC takes its family along (behind it); a dropped one drops it.
    std::sort(g_order, g_order + n, [](uint16_t a, uint16_t b) { return g_snap[a].index > g_snap[b].index; });
    size_t n_due = 0, n_gone = 0, n_drop = 0;
    {
        std::lock_guard lock(g_mu);
        // 3a. observer_hold_family's gate: a release to user 2's session whose parent it has not got, and whose
        //     parent is not released to it in this very pass, waits for its parent.
        if (live && g_known_session == live && !g_fm_unknown_off.load(std::memory_order_relaxed)) {
            bool any = false;
            for (size_t k = 0; k < n; ++k) {
                NpcDecision& d = g_dec[k];
                if (d.step != ReleaseStep::Release) continue;
                d.present = g_npc_table.locate(g_snap[k].e.stamp, g_snap[k].index) < g_npc_table.size();
                d.blocked = d.present && d.parent && !g_known.contains(d.parent);
                any = any || d.blocked;
            }
            for (int round = 0; any && round < 8; ++round) {
                bool changed = false;
                for (size_t k = 0; k < n; ++k) {
                    NpcDecision& d = g_dec[k];
                    if (!d.blocked) continue;
                    for (size_t q = 0; q < n; ++q) {
                        const NpcDecision& p = g_dec[q];
                        if (q != k && p.step == ReleaseStep::Release && p.present && !p.blocked &&
                            g_snap[q].e.key == d.parent && g_snap[q].e.observer == g_snap[k].e.observer) {
                            d.blocked = false;
                            changed = true;
                            break;
                        }
                    }
                }
                if (!changed) break;
            }
        }
        const size_t fam_room0 = g_fam_table.room() - std::min(g_fam_table.room(), g_fam_reserved);
        size_t fam_used = 0;
        for (size_t x = 0; x < n; ++x) {
            const size_t k = g_order[x];
            NpcDecision& d = g_dec[k];
            if (d.step == ReleaseStep::Keep && !d.note_ctrl && !d.note_slow && !d.note_u2) continue;
            const size_t i = g_npc_table.locate(g_snap[k].e.stamp, g_snap[k].index);
            if (i >= g_npc_table.size()) continue;  // gone or refreshed meanwhile: decided again next time
            d.applied = true;
            HoldEntry& cur = g_npc_table.at(i);
            if (d.step == ReleaseStep::Keep) {
                if (d.note_ctrl) cur.ctrl_change_noted = true;
                if (d.note_slow) cur.timeout_noted = true;
                if (d.note_u2) cur.u2_withheld_noted = true;
                continue;
            }
            if (d.step == ReleaseStep::Release && d.blocked) {
                if (fam_mode < 2) {
                    d.blocked_how = 3;  // probe: counted, released as before
                } else if (fam_used < fam_room0) {
                    // It waits for its parent in the family table (released with it, or after it reaches user 2).
                    HoldEntry fe = cur;
                    fe.npc = false;
                    fe.family = true;
                    fe.npc_origin = true;
                    fe.parent = d.parent;
                    fe.family_why = static_cast<uint8_t>(FamilyWhy::ReleaseBlocked);
                    fe.wait_since_ms = now;
                    (void)g_fam_table.add(fe);
                    ++fam_used;
                    d.blocked_how = 1;
                    g_npc_table.remove_at(i);
                    continue;
                } else {
                    d.blocked_how = 2;  // no room: released now, as without the key
                }
            }
            if (d.step == ReleaseStep::Release) {
                NpcDue due{cur.key,   cur.observer,  d.observer_key, d.age, cur.type, cur.observer_host,
                           d.controller_now, d.kind, d.why, cur.defer, cur.defer && no_2762_yet};
                due.parent = d.parent;
                due.src = cur;
                g_due[n_due++] = due;
            } else {
                g_npc_dropped.fetch_add(1);
                if (cur.defer) {
                    g_ld_dropped.fetch_add(1);
                    // Per reason (P8 S14 regression): a despawn, user 2 gone or another epoch cannot leave an NPC
                    // invisible; anything else (out of range after the 2762, unreadable, the observer session's
                    // user changed or unreadable while user 2 is still there: review L5) might.
                    const bool despawned = std::strcmp(d.why, "despawned") == 0;
                    const bool gone = std::strcmp(d.why, "another guest epoch") == 0 ||
                                      (!user2_present && (std::strcmp(d.why, "observer gone") == 0 ||
                                                          std::strcmp(d.why, "observer's user changed") == 0));
                    (despawned ? g_ld_drop_despawned : gone ? g_ld_drop_gone : g_ld_drop_other).fetch_add(1);
                }
                // Its family goes with it (below, one walk per level).
                if (n_drop < kDueCapacity) g_drop_roots[n_drop++] = {cur.key, cur.observer, 0, 0};
            }
            g_npc_table.remove_at(i);
        }
        g_npc_size.store(g_npc_table.size());
        for (size_t k = 0; k < n_p; ++k) {
            FamSnap& ps = g_psnap[k];
            if (ps.step == ReleaseStep::Keep) continue;
            const size_t i = g_fam_table.locate(ps.e.stamp, ps.index);
            if (i >= g_fam_table.size()) continue;  // gone (with its parent) or refreshed meanwhile
            ps.applied = true;
            const HoldEntry pe = g_fam_table.at(i);
            g_fam_table.remove_at(i);
            if (ps.step == ReleaseStep::Release && n_due < kDueCapacity) {
                NpcDue dd{pe.key, pe.observer, ps.observer_key, ps.age, pe.type, pe.observer_host, pe.controller,
                          NpcRelease::None, ps.why, pe.defer, false};
                dd.family = true;
                dd.parent = pe.parent;
                dd.fkind = ps.kind;
                dd.npc_origin = pe.npc_origin;
                dd.src = pe;
                g_due[n_due++] = dd;
            } else if (ps.step == ReleaseStep::Drop && n_drop < kDueCapacity) {
                // Its own members go with it (noted as "its parent's entry was dropped").
                g_drop_roots[n_drop++] = {pe.key, pe.observer, 0, 0};
            }
        }
        // Whatever waits behind the releases follows them; behind the drops, goes with them (any depth; one walk
        // of the family table per level).
        if (g_fam_table.size() && n_due) {
            size_t nr = 0;
            for (size_t x = 0; x < n_due; ++x) {
                g_roots_a[nr++] = {g_due[x].key, g_due[x].observer, g_due[x].observer_key, g_due[x].depth};
            }
            take_family_levels_locked(nr, true, now, n_due, n_gone);
        }
        if (g_fam_table.size() && n_drop) {
            std::copy(g_drop_roots, g_drop_roots + n_drop, g_roots_a);
            take_family_levels_locked(n_drop, false, now, n_due, n_gone);
        }
        g_fam_size.store(g_fam_table.size());
    }
    // 4. The notes (a ring push each) and the releases, outside the lock.
    const uintptr_t acks = ack_session();
    for (size_t k = 0; k < n; ++k) {
        const NpcDecision& d = g_dec[k];
        if (!d.applied) continue;
        const HoldEntry& e = g_snap[k].e;
        if (d.note_ctrl) {
            g_npc_ctrl_changed.fetch_add(1);
            note(g_npc_other_logged, kMaxNpcOtherLogged, kNoteNpcCtrlChanged,
                 {e.key, e.controller, d.controller_now, e.observer});
        }
        if (d.note_slow) {
            note(g_npc_other_logged, kMaxNpcOtherLogged, kNoteNpcStillHeld, {e.key, e.observer, d.age, ptr_bits(d.why)});
        }
        if (d.note_u2) {
            g_npc_withheld_u2.fetch_add(1);
            note(g_npc_other_logged, kMaxNpcOtherLogged, kNoteNpcWithheldU2,
                 {e.key, e.observer, d.controller_now, d.age});
        }
        if (d.blocked_how == 1) {
            g_fm_converted.fetch_add(1);
            note(g_fm_other_logged, kMaxFamOtherLogged, kNoteFamOther, {7, e.key, d.parent, e.observer});
        } else if (d.blocked_how == 2) {
            g_fm_blocked_native.fetch_add(1);
            note(g_fm_other_logged, kMaxFamOtherLogged, kNoteFamOther, {8, e.key, d.parent, e.observer});
        } else if (d.blocked_how == 3) {
            g_fm_would_block.fetch_add(1);
            note(g_fm_logged, kMaxFamLogged, kNoteFamOther, {10, e.key, d.parent, e.observer});
        }
        if (d.step == ReleaseStep::Drop) {
            note(g_npc_other_logged, kMaxNpcOtherLogged, kNoteNpcDropped,
                 {e.key, e.type, e.controller, e.observer, static_cast<uint64_t>(e.observer_host), d.age,
                  ptr_bits(d.why)});
            // observer_hold_acks: no 2005 will come for it: what was kept for it goes.
            if (acks && e.observer == acks) observer_hold_acks_drop(e.key);
        }
    }
    // observer_hold_family: dropped with their parent, or on their own.
    auto member_dropped = [&](const HoldEntry& pe, uint64_t age, const char* why) {
        g_fm_dropped.fetch_add(1);
        note(g_fm_other_logged, kMaxFamOtherLogged, kNoteFamDropped,
             {pe.key, pe.parent, pe.observer, static_cast<uint64_t>(pe.observer_host), age, ptr_bits(why)});
        if (acks && pe.observer == acks) observer_hold_acks_drop(pe.key);
    };
    for (size_t k = 0; k < n_gone; ++k) {
        const HoldEntry& pe = g_pgone[k];
        member_dropped(pe, now >= pe.since_ms ? now - pe.since_ms : 0, "its parent's entry was dropped");
    }
    for (size_t k = 0; k < n_p; ++k) {
        const FamSnap& ps = g_psnap[k];
        if (ps.applied && ps.step == ReleaseStep::Drop) member_dropped(ps.e, ps.age, ps.why);
    }
    if (n_due) n_due = drop_despawned_members(*sam, n_due, acks);
    if (n_due) n_due = gate_releases(*sam, n_due, now, where);  // S35 publication_gate: every exit, one admission
    if (n_due) release_npcs(g_due, n_due, where);
    const uint64_t us = qpc_us() - t0;
    g_npc_pass_us_sum.fetch_add(us, std::memory_order_relaxed);
    store_max(g_npc_pass_us_max, us);
}

// The budgeted pass, at most every hold::kNpcPassMs (any thread that may
// release: the StartActionReq handler's or the game's NotifyAppear thread).
void npc_periodic(bool allow_release, const char* where) {
    const uint64_t now = now_ms();
    uint64_t last = g_npc_last_pass.load(std::memory_order_relaxed);
    if (now - last < hold::kNpcPassMs) return;
    if (!g_npc_last_pass.compare_exchange_strong(last, now, std::memory_order_relaxed)) return;
    npc_pass(0, allow_release, where);
    // S35 probe (review 4): would the refused ones have recovered within the retention? Also with empty tables (the
    // releases already went out); its own turn of the pass lock, protected reads only, never a game call.
    if (pub_gate() == pubg::Mode::Probe && g_pub_shadow_size.load(std::memory_order_relaxed) && !g_npc_busy.test_and_set(std::memory_order_acquire)) {
        if (const auto sam = sam_now(true)) pub_shadow_sweep(*sam, now);
        g_npc_busy.clear(std::memory_order_release);
    }
}

// TrocTrStartActionReq::vf2's work after the original returned (its action
// may just have set the restore byte). key: the Req's actor key (0 = unknown).
// notify_thread_rule=1: only a thread the game itself used for NotifyAppear
// releases here; on any other one the releases wait for the tail of the next
// native NotifyAppear. 0 (default): this handler's thread releases (as before).
void after_start_action(uint32_t key) {
    g_action_calls.fetch_add(1, std::memory_order_relaxed);
    sweep_children("after StartActionReq", true);  // D-53
    if (g_char_size.load(std::memory_order_relaxed)) char_pass(true, "after StartActionReq");  // character_hold
    if (g_settle_size.load(std::memory_order_relaxed)) settle_pass(true, "after StartActionReq");  // child_settle
    if (!g_observers.load(std::memory_order_relaxed) ||
        (!g_npc_size.load(std::memory_order_relaxed) && !g_fam_size.load(std::memory_order_relaxed) &&
         !g_pub_shadow_size.load(std::memory_order_relaxed))) {
        return;
    }
    if (!server_realm()) {
        g_sweep_other.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    // notify_thread_rule=0: the handler's own thread releases, as before the rule.
    const bool native = !g_thread_rule.load(std::memory_order_relaxed) || native_appear_thread();
    if (!native) g_npc_thread_deferred.fetch_add(1, std::memory_order_relaxed);
    if (key) npc_pass(key, native, "after StartActionReq");
    npc_periodic(native, "periodic, after StartActionReq");
}

// TrocTrStartActionReq::vf2(this, int* res, ctx*) -> res. The Req's key is
// read from its packet before the original runs (observer_hold only).
int* __fastcall start_action_detour(void* self, int* res, void* ctx, void* r9) noexcept {
    uint32_t key = 0, u2e_key = 0;
    // S33: retorno del handler externo; NO demuestra aceptación por ServerStartActionLogic.
    const bool u2e = user2_stages_wants_start_action();
    if (u2e || (g_observers.load(std::memory_order_relaxed) &&
                (g_npc_size.load(std::memory_order_relaxed) || g_fam_size.load(std::memory_order_relaxed)))) {
        u2e_key = start_action_req_key(reinterpret_cast<uintptr_t>(ctx)).value_or(0);
        if (g_observers.load(std::memory_order_relaxed)) key = u2e_key;
    }
    int* r = g_action.unsafe_call<int*>(self, res, ctx, r9);
    if (u2e && u2e_key) {
        user2_stages_start_action_done(u2e_key, r ? game::fast<int32_t>(reinterpret_cast<uintptr_t>(r)).value_or(-1) : -1);
    }
    try {
        after_start_action(key);
    } catch (...) {
        g_errors.fetch_add(1, std::memory_order_relaxed);
    }
    return r;
}

// child_hold_server_tick's body (check_thread = false only in the tests).
void server_tick_body(bool check_thread) {
    const uint64_t now = now_ms();
    const bool on_thread = !check_thread || GetCurrentThreadId() == server_thread_id();
    if (g_size.load(std::memory_order_relaxed) && now - g_last_tick.load(std::memory_order_relaxed) >= kTickMs) {
        g_last_tick.store(now, std::memory_order_relaxed);
        if (on_thread) sweep_children("fallback", false);
    }
    // character_hold: the receiving thread drops and notes only (NotifyAppear is not called there).
    if (g_char_size.load(std::memory_order_relaxed) && on_thread) {
        uint64_t last = g_char_last_fallback.load(std::memory_order_relaxed);
        if (now - last >= hold::kNpcFallbackMs &&
            g_char_last_fallback.compare_exchange_strong(last, now, std::memory_order_relaxed)) {
            char_pass(false, "fallback");
        }
    }
    // child_settle: as character_hold, the receiving thread drops only.
    if (g_settle_size.load(std::memory_order_relaxed) && on_thread) {
        uint64_t last = g_settle_last_fallback.load(std::memory_order_relaxed);
        if (now - last >= hold::kNpcFallbackMs &&
            g_settle_last_fallback.compare_exchange_strong(last, now, std::memory_order_relaxed)) {
            settle_pass(false, "fallback");
        }
    }
    // observer_hold (M5): the receiving thread is a server-realm thread too,
    // but the engine's logic (NotifyAppear included) runs on another one
    // (T29232): no NotifyAppear here, only drops and notes; due releases wait
    // for the next pass after a StartActionReq or a NotifyAppear.
    if (g_observers.load(std::memory_order_relaxed) &&
        (g_npc_size.load(std::memory_order_relaxed) || g_fam_size.load(std::memory_order_relaxed)) && on_thread) {
        uint64_t last = g_npc_last_fallback.load(std::memory_order_relaxed);
        if (now - last >= hold::kNpcFallbackMs &&
            g_npc_last_fallback.compare_exchange_strong(last, now, std::memory_order_relaxed)) {
            npc_pass(0, false, "fallback");
        }
    }
}

bool code_ok(uintptr_t rva, const uint8_t* bytes, size_t n, const char* what) {
    uint8_t actual[64] = {};
    if (n <= sizeof actual && game::safe_read(g_base + rva, actual, n) && std::memcmp(actual, bytes, n) == 0) {
        return true;
    }
    log::error("Session2 child hold: {} (exe+0x{:X}) is not the expected code; no hold", what, rva);
    return false;
}

}  // namespace

bool child_hold_install() { return child_hold_install(true, false, false); }

bool child_hold_install(bool children, bool observers) { return child_hold_install(children, observers, false); }

bool child_hold_install(bool children, bool observers, bool characters) {
    const uint32_t settle_ms = g_settle_ms.load();
    if (!children && !observers && !characters && !settle_ms) return false;
    if (g_active.load()) return true;
    g_profile = child_hold_profile();
    if (!g_profile || !game::validate_native_catalog()) {
        log::error("Session2 child hold: unsupported build or native message catalogue; no hold");
        return false;
    }
    // Before the hooks go in (the detours read them).
    g_children.store(children);
    g_observers.store(observers);
    g_characters.store(characters);
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    for (const auto& check : g_profile->checks) {
        if (!code_ok(check.rva, check.bytes.data(), check.bytes.size(), check.what)) return false;
    }
    uintptr_t slot = 0;
    if (!peek(g_base + g_profile->action_vtable + 0x10, slot) || slot != g_base + g_profile->action) {
        log::error("Session2 child hold: TrocTrStartActionReq's vf2 is not exe+0x{:X}; no hold", g_profile->action);
        return false;
    }
    g_notify = safetyhook::create_inline(reinterpret_cast<void*>(g_base + g_profile->notify),
                                         reinterpret_cast<void*>(&notify_detour), SafetyHookInline::StartDisabled);
    g_action = safetyhook::create_inline(reinterpret_cast<void*>(g_base + g_profile->action),
                                         reinterpret_cast<void*>(&start_action_detour), SafetyHookInline::StartDisabled);
    // The release side first: inert while nothing is held.
    if (!g_notify || !g_action || !g_action.enable()) {
        g_notify = {};
        g_action = {};
        log::error("Session2 child hold: cannot hook NotifyAppear / StartActionReq; no hold");
        return false;
    }
    if (!g_notify.enable()) {
        (void)g_action.disable();  // disabled, not destroyed: a thread may be inside
        log::error("Session2 child hold: cannot hook NotifyAppear; no hold");
        return false;
    }
    g_active.store(true);
    if (children) {
        log::info("Session2 child hold ON (D-53, any owner): a user's child (the host's or user 2's) with restore 0 "
                  "goes only to its owner's session; every other recipient gets it once its first action is accepted "
                  "(hooks exe+0x{:X} NotifyAppear, exe+0x{:X} StartActionReq::vf2; table of {})",
                  g_profile->notify, g_profile->action, hold::kTableCapacity);
    }
    if (observers) {
        log::info("Session2 observer hold ON (S3): an NPC (no owner) whose controller [actor+0x90] is the host's or "
                  "user 2's user key and whose restore byte is 0 goes at once to its controller's session only; every "
                  "other recipient gets a fresh native 2005 once its first action is accepted (restore 1), once it "
                  "controls it, or after {} ms with restore 0; dropped on despawn/observer gone/out of range/epoch; "
                  "announced natively instead of dropped while still in range. Same hooks (exe+0x{:X}, exe+0x{:X}); "
                  "table of {} (room reserved in the split); passes: the Req's key after each StartActionReq plus "
                  "{} entries every {} ms (also after NotifyAppear), SEH reads, decided outside the lock{}",
                  hold::kNpcTimeoutMs, g_profile->notify, g_profile->action, hold::kNpcTableCapacity, hold::kNpcPassBudget,
                  hold::kNpcPassMs, children ? "" : " | child_hold=0: users' children are NOT held");
    }
    if (characters) {
        log::info("Session2 character hold ON: a user's main character (0xA..., owner a validated user whose +0x{:X} "
                  "is that actor) with restore 0 goes at once to its owner's session(s) only (its own login is never "
                  "delayed); every other recipient gets a fresh native 2005 once its first action is accepted "
                  "(restore 1), or WITH restore 0 after {} ms (warning line); dropped on despawn/logout/observer "
                  "gone/out of range (field change)/epoch; announced natively instead of dropped while still in range. "
                  "Same hooks (exe+0x{:X}, exe+0x{:X}); table of {} (room reserved in the split); pieces without CC are "
                  "not held{}",
                  hold::kUserCharacter, hold::kCharTimeoutMs, g_profile->notify, g_profile->action, hold::kCharTableCapacity,
                  children ? "" : " | child_hold=0: users' children are NOT held");
    }
    if (settle_ms) {
        log::info("Session2 child settle ON (child_settle_ms={}): a user's child (0xB, owner a validated user, type "
                  "4/5/6, any restore byte) that D-53 does not hold is withheld from a session while its owner's main "
                  "character goes in the same NotifyAppear, was announced there less than {} ms ago, or is still "
                  "withheld there (character_hold); released by a native NotifyAppear([observer],[child]) {} ms after "
                  "that character's announcement (after StartActionReq / at the tail of a native NotifyAppear), "
                  "natively after {} ms at most while in range; D-53's releases wait the same; table of {}{}",
                  settle_ms, settle_ms, settle_ms, cst::max_wait_ms(settle_ms), hold::kSettleTableCapacity,
                  children ? "" : " | child_hold=0: restore-0 children are settled too (not held for an action)");
    }
    if (g_thread_rule.load()) {
        log::info("Session2 child hold: notify_thread_rule=1: the holds call NotifyAppear only on a thread the game "
                  "itself used for it (seen from exe+0x{:X} / exe+0x{:X}); after a StartActionReq elsewhere the "
                  "release waits for the tail of the next native NotifyAppear (WRN past {} ms)",
                  g_profile->caller_new, g_profile->caller_moving, hold::kDeferWarnMs);
    } else {
        log::info("Session2 child hold: notify_thread_rule=0 (default): releases on the StartActionReq handler's "
                  "thread, as before the rule (a due release waiting longer than {} ms for a thread that may call "
                  "NotifyAppear gives a WRN line)",
                  hold::kDeferWarnMs);
    }
    return true;
}

void child_hold_set_thread_rule(bool on) { g_thread_rule.store(on); }
bool child_hold_thread_rule() { return g_thread_rule.load(); }
namespace {
// Not verified on 3527/3549 nor on 3576: the publication gate and the key retirement (its hook at a 2976 address).
// Only 2976 (and the tests' seams): a build other than 3527 must not fall through to them (3576 did, with != v3527).
bool legacy_hold_policies_supported() noexcept {
    return g_seams || game::current_build() == game::Build::v2976;
}
void note_unported_policy(const char* name) {
    log::warn("Session2 child hold: {} is not ported to this build (only 2976) and stays off", name);
}
}  // namespace
void child_hold_set_settle_ms(uint32_t ms) {
    g_settle_ms.store(std::min<uint32_t>(ms, 60000));
}

void child_hold_set_load_defer(uint8_t mode) {
    g_load_defer.store(std::min<uint8_t>(mode, 2));
}
uint8_t child_hold_load_defer() { return g_load_defer.load(); }
void child_hold_set_family(uint8_t mode) {
    g_family.store(std::min<uint8_t>(mode, 2));
}
uint8_t child_hold_family() { return g_family.load(); }
void child_hold_set_publication_gate(uint8_t mode, uint32_t retain_max_ms) {
    if (mode && !legacy_hold_policies_supported()) {
        note_unported_policy("publication_gate");
        mode = 0;
    }
    g_pub_gate.store(std::min<uint8_t>(mode, 2));
    // Experimental bound (publication_retain_max_ms): 5 s .. 10 min; the default 60 s.
    g_pub_retain_ms.store(std::clamp<uint64_t>(retain_max_ms, 5000, 600000));
    if (mode && !g_seams) {
        log::info("Session2: publication_gate {}: no observer_hold / observer_hold_family exit announces to an observer "
                  "that does not control it an actor whose state is not proven complete (restore 0, CC unreadable, "
                  "actor / controller unreadable, a parent withheld / refused / incomplete); {} (retained at most {} ms, "
                  "then dropped WITHOUT publishing; full tables withhold without an entry)",
                  mode >= 2 ? "ON" : "PROBE",
                  mode >= 2 ? "such a release is RETAINED" : "such a release is counted and logged as WOULD RETAIN, "
                                                           "and published as before",
                  g_pub_retain_ms.load());
    }
}
uint8_t child_hold_publication_gate() { return g_pub_gate.load(); }

void child_hold_on_user2_out(uint16_t opcode, std::span<const uint8_t> payload) noexcept {
    if (opcode != fam::kOpAnnounce && opcode != fam::kOpRemove && opcode != fam::kOpMoveField) return;
    if (!g_active.load(std::memory_order_relaxed) || !g_observers.load(std::memory_order_relaxed)) return;
    try {
        const uint32_t epoch = server_epoch();
        // 1. The orphan count (analyze_capture.py `orphans` on what user 2 is given), whatever the family key.
        fam::OrphanSeen first;
        size_t records = 0, orphans = 0;
        {
            std::lock_guard lock(g_out_mu);
            if (g_out_epoch != epoch) {
                g_out_count.clear();
                g_out_epoch = epoch;
            }
            if (opcode == fam::kOpAnnounce) {
                const auto r = g_out_count.on_2005(payload);
                records = r.records;
                orphans = r.orphans;
                first = r.first;
            } else if (opcode == fam::kOpRemove) {
                (void)g_out_count.on_2516(payload);
            } else {
                g_out_count.clear();  // review 4: a field change: its client starts with nothing
            }
        }
        if (opcode == fam::kOpAnnounce) {
            g_out_2005.fetch_add(1, std::memory_order_relaxed);
            g_out_records.fetch_add(records, std::memory_order_relaxed);
            if (orphans) {
                g_out_orphans.fetch_add(orphans, std::memory_order_relaxed);
                note(g_out_logged, kMaxOutOrphanLogged, kNoteOutOrphan,
                     {first.key, first.type, first.parent, records, orphans});
            }
        } else if (opcode == fam::kOpRemove) {
            g_out_2516.fetch_add(1, std::memory_order_relaxed);
        } else {
            g_out_2174.fetch_add(1, std::memory_order_relaxed);
        }
        // 2. observer_hold_family: what user 2 has (its 2005s add, its 2516s remove, a 2174 empties it).
        if (!g_family.load(std::memory_order_relaxed)) return;
        const uintptr_t s2 = server_live_session2();
        if (!s2) return;
        std::lock_guard lock(g_mu);
        known_sync_locked(s2, epoch);
        if (opcode == fam::kOpAnnounce) {
            const bool was = g_known.overflow();
            fam::scan_2005(payload, [](const fam::Record& r) { (void)g_known.insert(r.key); });
            if (!was && g_known.overflow()) {
                g_fm_known_overflow.fetch_add(1, std::memory_order_relaxed);
                note(g_fm_other_logged, kMaxFamOtherLogged, kNoteFamOther, {9, hold::kFamilyKnownSlots * 3 / 4});
            }
        } else if (opcode == fam::kOpRemove) {
            fam::removed_keys(payload, [](uint32_t k) { (void)g_known.erase(k); });
        } else {
            // Review 4: MoveFieldAck 2174, a field change for user 2: whatever its client had may be gone without
            // a 2516, and the server announces the new field's actors again. A set left full would also fail open
            // for good. (S14/S15 captures: clearing here changes no orphan count, native 0 stays 0.)
            g_known.clear();
        }
    } catch (...) {
        g_errors.fetch_add(1, std::memory_order_relaxed);
    }
}

void child_hold_note_user2_loading(bool loading) noexcept {
    const bool was = g_user2_loading.exchange(loading, std::memory_order_relaxed);
    if (was == loading) return;
    // The load's window (review M1/L2): its start bounds the wait (hold::kLoadDeferMaxMs), its end restarts
    // observer_hold's restore-0 timeout of the entries it held.
    const uint64_t now = now_ms();
    if (loading) {
        g_load_stuck_noted.store(false, std::memory_order_relaxed);
        g_load_start_ms.store(now ? now : 1, std::memory_order_relaxed);
    } else {
        g_load_start_ms.store(0, std::memory_order_relaxed);
        g_load_end_ms.store(now ? now : 1, std::memory_order_relaxed);
    }
    if (!g_load_defer.load(std::memory_order_relaxed) || !g_observers.load(std::memory_order_relaxed)) return;
    if (loading) g_ld_loads.fetch_add(1, std::memory_order_relaxed);
    // A few per session (login, each field change): a lock-free ring push, any thread.
    note(g_ld_phase_logged, kMaxLoadPhaseLogged, kNoteLoadPhase,
         {static_cast<uint64_t>(loading), g_ld_loads.load(std::memory_order_relaxed),
          g_npc_size.load(std::memory_order_relaxed)});
}
bool child_hold_user2_loading() noexcept {
    if (!g_user2_loading.load(std::memory_order_relaxed)) return false;
    const uint64_t start = g_load_start_ms.load(std::memory_order_relaxed);
    const uint64_t now = now_ms();
    return !start || now < start || now - start < hold::kLoadDeferMaxMs;
}
uint32_t child_hold_settle_ms() { return g_settle_ms.load(); }
bool child_settle_active() { return g_active.load() && g_settle_ms.load() != 0; }

const char* reannounce_name(Reannounce r) {
    switch (r) {
        case Reannounce::Queued: return "queued";
        case Reannounce::AlreadyHeld: return "already held for session 2";
        case Reannounce::NotActive: return "child_settle off";
        case Reannounce::NoUser2: return "no live session 2 / user 2";
        case Reannounce::Unreadable: return "actor manager unreadable";
        case Reannounce::NotCandidate: return "not a user's child (type 4/5/6, owner's character known)";
        case Reannounce::NotHosts: return "not the host's child";
        case Reannounce::Full: return "settle table full";
    }
    return "?";
}

std::atomic<uint64_t> g_settle_reannounced{0};

Reannounce child_settle_reannounce(uint32_t key, uint32_t delay_ms, bool dry_run) {
    if (!child_settle_active()) return Reannounce::NotActive;
    const uintptr_t session = server_live_session2();
    uintptr_t user2 = 0;
    if (!session || !server_user2(user2) || !user2) return Reannounce::NoUser2;
    uintptr_t host = 0;
    const uint32_t host_key = host_key_now(host);
    const auto sam = sam_now(true);
    if (!sam) return Reannounce::Unreadable;
    const uintptr_t user_vt = user_vtable_now();
    const SettleCandidate sc = settle_candidate(*sam, key, user2, host, host_key, user_vt);
    if (!sc.ok) return Reannounce::NotCandidate;
    if (sc.owner_who != OwnerWho::Host) return Reannounce::NotHosts;
    if (dry_run) return Reannounce::Queued;
    const uint64_t now = now_ms();
    HoldEntry e;
    e.key = key;
    e.observer = session;
    e.observer_user = user2;
    e.owner = sc.owner;
    e.owner_who = sc.owner_who;
    e.observer_host = false;
    e.epoch = server_epoch();
    e.since_ms = now;
    e.type = sc.type;
    e.settle = true;
    e.main_key = sc.main_key;
    e.actor = sc.actor;
    e.not_before_ms = now + delay_ms;
    std::lock_guard lock(g_mu);
    if (g_settle_table.room() <= g_settle_reserved) return Reannounce::Full;
    const auto added = g_settle_table.add(e);
    g_settle_size.store(g_settle_table.size());
    if (added == SettleHoldTable::Add::Duplicate) return Reannounce::AlreadyHeld;
    if (added == SettleHoldTable::Add::Full) return Reannounce::Full;
    g_settle_reannounced.fetch_add(1);
    return Reannounce::Queued;
}

std::optional<uint32_t> child_hold_actor_parent(uintptr_t actor) noexcept {
    const game::FastReads m;
    const auto key = m.rd<uint32_t>(actor + hold::kActorKey);
    return key ? family_parent_with(m, actor, *key, piece_parent_with(m, actor)) : std::nullopt;
}
namespace {
// S33 review: a retired key born again is noted in the 0x2792A7B mid hook and settled outside it (pruning its old
// packets from the queue is vector work with CRT memcpy: never inside a mid hook). Field-by-field ring (copy_event).
p8p::EventRing<1024> g_born_retired;
std::atomic<uint64_t> g_born_retired_lost{0};
}  // namespace
void child_hold_actor_born(uint32_t epoch, uint64_t generation, uint32_t key) noexcept {
    if (!observer_hold_acks_retired(key)) return;  // only a tombstoned key has anything to settle
    p8p::Event e;
    e.v[0] = epoch;
    e.v[1] = generation;
    e.v[2] = key;
    if (!g_born_retired.push(e)) g_born_retired_lost.fetch_add(1, std::memory_order_relaxed);
}
void child_hold_settle_births() noexcept {
    p8p::Event e;
    while (g_born_retired.pop(e)) {
        child_hold_actor_created(static_cast<uint32_t>(e.v[0]), e.v[1], static_cast<uint32_t>(e.v[2]));
    }
}
void child_hold_set_retirement(bool on) noexcept {
    observer_hold_acks_set_retirement(on && legacy_hold_policies_supported());
}
void child_hold_set_npc_family_observe(bool on) noexcept {
    g_npc_family_observe.store(on && legacy_hold_policies_supported(), std::memory_order_relaxed);
}
bool child_hold_retired(uint32_t key) noexcept { return observer_hold_acks_retired(key); }
void child_hold_actor_created(uint32_t epoch, uint64_t generation, uint32_t key) noexcept {
    auto publication = observer_hold_acks_publication_guard();
    if (!publication.owns_lock() || epoch != server_epoch()) return;
    // Antes de permitir reutilización explícita, quitar los bytes de la
    // encarnación anterior que todavía no ha recogido el hilo de red.
    if (observer_hold_acks_retired(key) && !server_prune_retired_outgoing()) return;
    observer_hold_acks_actor_created(epoch, generation, key);
}
bool child_hold_retire_family(uint32_t epoch, uint64_t generation,
                              std::span<const uint32_t> keys, bool from_publication) noexcept {
    auto publication = observer_hold_acks_publication_guard();
    if (!publication.owns_lock() || epoch != server_epoch() || keys.empty() ||
        !observer_hold_acks_publications_idle(from_publication)) return false; // nada mutado: reintentar en otro Troc
    try {
        // El llamador prevalidó EXACTAMENTE estas claves en scopes nativos. No ampliar
        // aquí: cancelar un hijo adicional sin incluirlo en los Logout dejaría un actor vivo invisible.
        // Si falta un vínculo observado, rechazo atómico antes de tombstones o colas.
        const auto all = keys;
        std::lock_guard lock(g_mu);
        for (size_t i = 0; i < g_fam_table.size(); ++i) {
            const auto& e = g_fam_table.at(i);
            if (e.epoch == epoch && std::find(all.begin(), all.end(), e.parent) != all.end() &&
                std::find(all.begin(), all.end(), e.key) == all.end()) return false;
        }
        if (!observer_hold_acks_retire(epoch, generation, all)) return false;
        const auto drop = [&](const HoldEntry& e) {
            return e.epoch == epoch && std::find(all.begin(), all.end(), e.key) != all.end();
        };
        g_table.drop_if(drop);
        g_npc_table.drop_if(drop);
        g_fam_table.drop_if(drop);
        g_char_table.drop_if(drop);
        g_settle_table.drop_if(drop);
        for (const uint32_t key : all) (void)g_known.erase(key);
        g_size.store(g_table.size());
        g_npc_size.store(g_npc_table.size());
        g_fam_size.store(g_fam_table.size());
        g_char_size.store(g_char_table.size());
        g_settle_size.store(g_settle_table.size());
        return server_prune_retired_outgoing();
    } catch (...) {
        return false; // sin Logout: el llamador conserva el diagnóstico
    }
}

int child_hold_held_children(uint32_t epoch, std::span<const uint32_t> parents, uint32_t* keys, uint32_t* parent_of,
                             size_t cap) noexcept {
    if (!g_active.load(std::memory_order_relaxed) || parents.empty()) return 0;
    if (!g_fam_size.load(std::memory_order_relaxed)) return 0;
    try {
        std::unique_lock lock(g_mu, std::try_to_lock);
        if (!lock.owns_lock()) return -1;
        int n = 0;
        for (size_t i = 0; i < g_fam_table.size(); ++i) {
            const auto& e = g_fam_table.at(i);
            if (e.epoch != epoch || std::find(parents.begin(), parents.end(), e.parent) == parents.end() ||
                std::find(parents.begin(), parents.end(), e.key) != parents.end()) {
                continue;
            }
            bool dup = false;
            for (int j = 0; j < n && static_cast<size_t>(j) < cap; ++j) dup = dup || keys[j] == e.key;
            if (dup) continue;
            if (static_cast<size_t>(n) < cap) {
                keys[n] = e.key;
                parent_of[n] = e.parent;
            }
            ++n;
        }
        return n;
    } catch (...) {
        return -1;
    }
}

bool child_hold_withheld(uint32_t key, uintptr_t observer) noexcept {
    if (!g_active.load(std::memory_order_relaxed)) return false;
    if (!g_size.load(std::memory_order_relaxed) && !g_settle_size.load(std::memory_order_relaxed)) return false;
    try {
        std::unique_lock lock(g_mu, std::try_to_lock);
        if (!lock.owns_lock()) return true;  // busy: as withheld (the caller skips, never waits)
        auto in = [&](const auto& t) {
            for (size_t i = 0; i < t.size(); ++i) {
                if (t.at(i).key == key && (!observer || t.at(i).observer == observer)) return true;
            }
            return false;
        };
        return in(g_table) || in(g_settle_table);
    } catch (...) {
        return true;
    }
}

std::optional<uintptr_t> hold_actor_owner(uint32_t key) {
    if (!g_active.load(std::memory_order_relaxed)) return std::nullopt;
    const auto sam = sam_now(true);
    if (!sam) return std::nullopt;
    const game::FastReads m;
    const auto actor = find_actor_with(m, *sam, key);
    if (!actor || !*actor) return std::nullopt;
    return m.rd<uintptr_t>(*actor + hold::kActorOwner);
}

bool child_hold_active() { return g_active.load(); }
bool observer_hold_active() { return g_active.load() && g_observers.load(); }
bool character_hold_active() { return g_active.load() && g_characters.load(); }

void child_hold_network_tick() noexcept {
    if (!g_active.load(std::memory_order_relaxed)) return;
    // Emptying the table calls nothing of the game, so the mod's network
    // thread does it (it always runs); the release itself only happens on the
    // game's server threads, where nothing comes after a logout (live C2 test
    // 2026-10-09: "still held 1" after user 2 left).
    if (g_size.load(std::memory_order_relaxed) || g_npc_size.load(std::memory_order_relaxed) ||
        g_char_size.load(std::memory_order_relaxed) || g_settle_size.load(std::memory_order_relaxed) ||
        g_fam_size.load(std::memory_order_relaxed)) {
        try {
            uintptr_t user2 = 0;
            const bool present = server_user2(user2);
            if (hold_drop_user2(present, server_logout_handed())) {
                std::lock_guard lock(g_mu);
                if (g_table.size()) (void)drop_user2_locked(present);
                if (g_npc_table.size() || g_fam_table.size()) (void)drop_npc_user2_locked(present);
                if (g_char_table.size()) (void)drop_char_user2_locked(present);
                if (g_settle_table.size()) (void)drop_settle_user2_locked(present);
            }
        } catch (...) {
            g_errors.fetch_add(1, std::memory_order_relaxed);
        }
    }
    // The queued log lines (M7), this tick's included.
    try {
        drain_notes();
    } catch (...) {
        g_errors.fetch_add(1, std::memory_order_relaxed);
    }
    // P8 review I3: a due release waiting for a thread that may call NotifyAppear.
    try {
        const hold::DeferWatch::Report r = g_defer.poll(now_ms(), hold::kDeferWarnMs);
        if (r.warn) {
            std::string what;
            if (r.kinds & hold::DeferWatch::kChild) what += " children";
            if (r.kinds & hold::DeferWatch::kNpc) what += " NPCs";
            if (r.kinds & hold::DeferWatch::kChar) what += " characters";
            out_line(true, std::format("Session2 child hold: a due release has waited {} ms for a thread that may call "
                                       "NotifyAppear (first left on thread {}; {} deferral(s);{}) | "
                                       "notify_thread_rule={}; native NotifyAppear threads {}",
                                       r.age_ms, r.tid, r.count, what.empty() ? std::string(" ?") : what,
                                       g_thread_rule.load() ? 1 : 0, g_native_count.load()));
        }
        if (r.resolved) {
            out_line(false, std::format("Session2 child hold: the deferred release(s) ran after {} ms", r.age_ms));
        }
    } catch (...) {
        g_errors.fetch_add(1, std::memory_order_relaxed);
    }
}

void child_hold_server_tick() noexcept {
    if (!g_active.load(std::memory_order_relaxed) ||
        (!g_size.load(std::memory_order_relaxed) && !g_npc_size.load(std::memory_order_relaxed) &&
         !g_char_size.load(std::memory_order_relaxed) && !g_settle_size.load(std::memory_order_relaxed) &&
         !g_fam_size.load(std::memory_order_relaxed))) {
        return;
    }
    try {
        server_tick_body(true);
    } catch (...) {
        g_errors.fetch_add(1, std::memory_order_relaxed);
    }
}

std::string child_hold_describe() {
    size_t still = 0, old = 0;
    {
        std::lock_guard lock(g_mu);
        still = g_table.size();
        old = g_table.older_than(GetTickCount64(), hold::kTimeoutMs);
    }
    std::string s = std::format(
        "child hold (D-53, any owner): NotifyAppear calls {} split {} | held {} (host's {}, user 2's {}; again {}, "
        "without entry {}; children sent to their owner {}, owner not a recipient {}) | released {} | dropped {} "
        "(announced natively {}, user 2 gone {}) | still held {} (>3 s {}, timeouts {})",
        g_calls.load(), g_split.load(), g_held.load(), g_held_host.load(), g_held_user2.load(), g_held_again.load(),
        g_unrecorded.load(), g_owner_sent.load(),
        g_owner_absent.load(), g_released.load(), g_dropped.load(), g_forgotten.load(), g_cleared.load(), still, old,
        g_timeouts.load());
    if (g_unreadable.load() || g_not_realm.load() || g_errors.load() || g_sweep_other.load()) {
        s += std::format(" | unchanged: recipient unreadable {}, not server realm {} | errors {} | sweeps refused off "
                         "the server thread {}",
                         g_unreadable.load(), g_not_realm.load(), g_errors.load(), g_sweep_other.load());
    }
    s += std::format(" | StartActionReq {}", g_action_calls.load());
    s += std::format(" | notify_thread_rule {} | NotifyAppear threads {} (other callers {}, slots full {}); releases "
                     "deferred to one: children {}, NPC passes {} | longest wait of a due release for such a thread "
                     "{} ms (open now {} ms)",
                     g_thread_rule.load() ? 1 : 0, g_native_count.load(), g_notify_foreign.load(),
                     g_native_full.load(), g_child_deferred.load(), g_npc_thread_deferred.load(), g_defer.max_ms(),
                     g_defer.open_ms(now_ms()));
    if (g_characters.load()) {
        size_t c_still = 0, c_old = 0;
        {
            std::lock_guard lock(g_mu);
            c_still = g_char_table.size();
            c_old = g_char_table.older_than(GetTickCount64(), hold::kTimeoutMs);
        }
        s += std::format(
            " | character hold: held {} (host's {}, user 2's {}; again {}; table full -> native {}, without entry {}; "
            "0xA keys not a user's main character {}) | released {} (restore 1 {}, TIMEOUT with restore 0 {}, "
            "natively instead of dropped {}; max wait {} ms; deferred to a NotifyAppear thread {}) | dropped {} "
            "(announced natively {}, user 2 gone {}) | still held {} (>3 s {})",
            g_char_held.load(), g_char_held_host.load(), g_char_held_user2.load(), g_char_again.load(),
            g_char_full.load(), g_char_unrecorded.load(), g_char_not_main.load(), g_char_released.load(),
            g_char_restore1.load(), g_char_timeouts.load(), g_char_native.load(), g_char_age_max.load(),
            g_char_deferred.load(), g_char_dropped.load(), g_char_forgotten.load(), g_char_cleared.load(), c_still,
            c_old);
    }
    if (g_settle_ms.load()) {
        size_t s_still = 0;
        {
            std::lock_guard lock(g_mu);
            s_still = g_settle_table.size();
        }
        s += std::format(
            " | child settle ({} ms): held {} (host's {}, user 2's {}; again {}; table full -> native {}, without entry "
            "{}) | released {} (settled {}, max wait {}, natively instead of dropped {}; longest {} ms; deferred to a "
            "NotifyAppear thread {}) | dropped {} (announced natively {}, user 2 gone {}) | D-53 releases that waited "
            "{} | still held {} | character announcements noted {} | released by the receiving thread after waiting "
            "{} ms for an allowed one {} | re-holds racing a release dropped {} | re-announces the guest asked for "
            "queued {}",
            g_settle_ms.load(), g_settle_held.load(), g_settle_held_host.load(), g_settle_held_user2.load(),
            g_settle_again.load(), g_settle_full.load(), g_settle_unrecorded.load(), g_settle_released.load(),
            g_settle_settled.load(), g_settle_max_wait.load(), g_settle_native.load(), g_settle_age_max.load(),
            g_settle_deferred.load(), g_settle_dropped.load(), g_settle_forgotten.load(), g_settle_cleared.load(),
            g_settle_d53_waited.load(), s_still, g_settle_announced.load(), hold::kDeferWarnMs,
            g_settle_fallback.load(), g_settle_raced.load(), g_settle_reannounced.load());
    }
    if (g_observers.load()) {
        size_t npc_still = 0, npc_old = 0, reserved = 0;
        {
            std::lock_guard lock(g_mu);
            npc_still = g_npc_table.size();
            npc_old = g_npc_table.older_than(GetTickCount64(), hold::kTimeoutMs);
            reserved = g_npc_reserved;
        }
        const uint64_t rel = g_npc_released.load();
        const uint64_t passes = g_npc_targeted.load() + g_npc_periodic.load();
        s += std::format(
            " | observer hold (S3): NPCs held {} (controller host {}, user 2 {}; again {}; table full -> native {}, "
            "without entry {}) | released {} in {} NotifyAppear (by control {}; mean {} ms, max {} ms; after the "
            "timeout with restore 0 {} (to the host with user 2 its controller {}: must be 0); natively instead of "
            "dropped {}) | withheld from the host (user 2 controls it, restore 0 past the timeout) {} | dropped {} (announced natively {}, user 2 "
            "gone {}) | controller changed while held {} | still held {} (>3 s {}, room reserved {}) | passes: "
            "targeted {}, budgeted {} ({} entries; mean {} us, max {} us; busy-skipped {}; releases deferred (the "
            "fallback, or not a NotifyAppear thread) {}) | split max {} us | log lines lost {}",
            g_npc_held.load(), g_npc_held_host_ctrl.load(), g_npc_held_user2_ctrl.load(), g_npc_again.load(),
            g_npc_full.load(), g_npc_unrecorded.load(), rel, g_npc_release_calls.load(), g_npc_released_ctrl.load(),
            rel ? g_npc_age_sum.load() / rel : 0, g_npc_age_max.load(), g_npc_timeouts.load(),
            g_npc_timeout_host_u2.load(), g_npc_native.load(), g_npc_withheld_u2.load(), g_npc_dropped.load(), g_npc_forgotten.load(), g_npc_cleared.load(), g_npc_ctrl_changed.load(), npc_still,
            npc_old, reserved, g_npc_targeted.load(), g_npc_periodic.load(), g_npc_evaluated.load(),
            passes ? g_npc_pass_us_sum.load() / passes : 0, g_npc_pass_us_max.load(), g_npc_busy_skips.load(),
            g_npc_deferred.load(), g_prepare_us_max.load(), g_notes_lost.load());
        if (const uint8_t ld = g_load_defer.load()) {
            size_t ld_now = 0;
            {
                std::lock_guard lock(g_mu);
                for (size_t i = 0; i < g_npc_table.size(); ++i) ld_now += g_npc_table.at(i).defer ? 1 : 0;
            }
            const uint64_t ld_rel = g_ld_released.load();
            s += std::format(
                " | observer load defer ({}): user 2 loading now {} (loads {}, STUCK past {} ms {}) | NPCs withheld "
                "while it loads {} "
                "(probe: would {}) | released {} (after its 2762 {}, AT THE CAP of {} ms {}; wait mean {} ms, max {} "
                "ms) | dropped {} (despawned {}, user 2 gone or new epoch {}, OTHER {}: out of range after its 2762 "
                "or unreadable, the NPC may be invisible) | withheld now {} | evaluations kept by the wait {}",
                ld >= 2 ? "on" : "probe", user2_loading_now(now_ms()) ? "yes" : "no", g_ld_loads.load(),
                hold::kLoadDeferMaxMs, g_ld_stuck.load(), g_ld_deferred.load(), g_ld_would.load(), ld_rel, ld_rel - std::min(ld_rel, g_ld_cap.load()),
                hold::kLoadDeferMaxMs, g_ld_cap.load(), ld_rel ? g_ld_wait_sum.load() / ld_rel : 0,
                g_ld_wait_max.load(), g_ld_dropped.load(), g_ld_drop_despawned.load(), g_ld_drop_gone.load(),
                g_ld_drop_other.load(), ld_now, g_ld_kept.load());
        }
        if (const uint8_t pm = g_family.load()) {
            size_t p_still = 0, p_reserved = 0, known = 0;
            {
                std::lock_guard lock(g_mu);
                p_still = g_fam_table.size();
                p_reserved = g_fam_reserved;
                known = g_known.size();
            }
            s += std::format(
                " | observer hold family ({}): members naming a parent seen {} (probe: WOULD be withheld {}, NPC "
                "releases that WOULD wait {}) | held {} (parent withheld in the same call {}, parent withheld {}, "
                "parent not with user 2 yet {}; again {}; table full -> native {}, WITHOUT an entry {}) | NPC "
                "releases that waited for their parent {} (table full -> released anyway {}) | left native: partial "
                "{}, UNLINKED {} | released {} (behind their parent {}, right after it reached user 2 {} in {} extra "
                "NotifyAppear, orphans of the host's session {}, PARENT NEVER CAME {}, AT THE MAX WAIT {}; longest "
                "{} ms; deferred to a NotifyAppear thread {}) | dropped {} (announced natively {}, user 2 gone {}) | "
                "still held {} (room reserved {}) | user 2 has {} key(s) (set FULL {}) | \"not announced yet\" rule "
                "{} | source probe: hierarchy parent == server +0xAC {}, DIFFERENT {}, only +0xAC {}",
                pm >= 2 ? "on" : "probe", g_fm_seen.load(), g_fm_would.load(), g_fm_would_block.load(),
                g_fm_held.load(), g_fm_held_in_call.load(), g_fm_held_held.load(), g_fm_held_unknown.load(),
                g_fm_again.load(), g_fm_full.load(), g_fm_unrecorded.load(), g_fm_converted.load(),
                g_fm_blocked_native.load(), g_fm_partial.load(), g_fm_unlinked.load(), g_fm_released.load(),
                g_fm_with_parent.load(), g_fm_after_parent.load(), g_fm_tail_calls.load(), g_fm_orphans.load(),
                g_fm_orphan_timeouts.load(), g_fm_max_age.load(), g_fm_age_max.load(), g_fm_deferred.load(),
                g_fm_dropped.load(), g_fm_forgotten.load(), g_fm_cleared.load(), p_still, p_reserved, known,
                g_fm_known_overflow.load(), g_fm_unknown_off.load() ? "SWITCHED OFF (too many in vain)" : "on",
                g_fm_ac_same.load(), g_fm_ac_other.load(), g_fm_ac_only.load());
        }
        // The count to verify the family order with (analyze_capture.py `orphans` on the host's side).
        s += std::format(" | family order: 2005 to user 2 {} ({} records), 2516 {}, 2174 {} | ORPHANS queued for user "
                         "2 {} (records naming a parent it had not been given; 0 = the native order)",
                         g_out_2005.load(), g_out_records.load(), g_out_2516.load(), g_out_2174.load(),
                         g_out_orphans.load());
    }
    if (const uint8_t pg = g_pub_gate.load()) {
        // S35 publication_gate: one parseable section (the counters of every exit, by verdict).
        const auto by = [](pubg::Verdict v) { return g_pg_by_verdict[static_cast<size_t>(v)].load(); };
        s += std::format(
            " | publication gate ({}): releases evaluated {} published {} gone {} refused {} (restore0 {}, cc_unknown {}, "
            "actor_unknown {}, controller_unknown {}, dependency {}, parent_in_batch {}) -> would {} retained {} dropped "
            "unpublished {} (expired {}, no room {}; longest retention {} ms, max {} ms) | native exits: full table "
            "withheld without entry {} (would {}) | CC unreadable NPC held {} (would {})",
            pg >= 2 ? "on" : "probe", g_pg_evaluated.load(), g_pg_published.load(), g_pg_gone.load(),
            by(pubg::Verdict::Restore0) + by(pubg::Verdict::CcUnknown) + by(pubg::Verdict::ActorUnknown) +
                by(pubg::Verdict::ControllerUnknown) + by(pubg::Verdict::Dependency) + by(pubg::Verdict::ParentInBatch),
            by(pubg::Verdict::Restore0), by(pubg::Verdict::CcUnknown), by(pubg::Verdict::ActorUnknown),
            by(pubg::Verdict::ControllerUnknown), by(pubg::Verdict::Dependency), by(pubg::Verdict::ParentInBatch),
            g_pg_would.load(), g_pg_retained.load(), g_pg_dropped_expired.load() + g_pg_dropped_no_room.load(),
            g_pg_dropped_expired.load(), g_pg_dropped_no_room.load(), g_pg_retain_max_ms.load(), g_pub_retain_ms.load(),
            g_pg_withheld_no_entry.load(), g_pg_would_no_entry.load(), g_pg_cc_unknown_held.load(),
            g_pg_cc_unknown_would.load());
        s += std::format(
            " | merged with a fresh hold {} | members dropped with an unpublished parent {} | UNCHECKED NotifyAppear "
            "(went out unchanged): actor manager unreadable {}, recipient unreadable {}, error {} | probe shadow: "
            "recorded {} (table full {}) would recover {} (slowest {} ms) would drop {} gone {} pending {}",
            g_pg_merged.load(), g_pg_members_dragged.load(), g_pg_unchecked_sam.load(), g_pg_unchecked_session.load(),
            g_pg_unchecked_error.load(), g_pg_shadow_recorded.load(), g_pg_shadow_full.load(),
            g_pg_shadow_recovered.load(), g_pg_shadow_recover_max_ms.load(), g_pg_shadow_would_drop.load(),
            g_pg_shadow_gone.load(), g_pub_shadow_size.load());
    }
    return s;
}

// ------------------------------------------------------------------ test seams

namespace hold_test {

void reset(const Seams* seams, bool children, bool observers) { reset(seams, children, observers, false); }

void reset(const Seams* seams, bool children, bool observers, bool characters) {
    child_hold_set_retirement(false);
    child_hold_set_npc_family_observe(false);
    g_seams = seams;
    g_base = seams ? seams->base : g_base;
    {
        std::lock_guard lock(g_mu);
        g_table.clear();
        g_npc_table.clear();
        g_npc_reserved = 0;
        g_npc_cursor = 0;
        g_char_table.clear();
        g_char_reserved = 0;
        g_settle_table.clear();
        g_settle_reserved = 0;
        g_fam_table.clear();
        g_fam_reserved = 0;
        g_known.clear();
        g_known_session = 0;
        g_known_epoch = 0;
    }
    {
        std::lock_guard lock(g_out_mu);
        g_out_count = {};
        g_out_epoch = 0;
    }
    g_fam_size = 0;
    g_family.store(0);
    g_fm_unknown_off.store(false);
    g_fm_valve_logged.store(0);
    for (auto* c : {&g_fm_seen, &g_fm_would, &g_fm_held, &g_fm_again, &g_fm_full, &g_fm_partial, &g_fm_unlinked,
                    &g_fm_released, &g_fm_orphans, &g_fm_dropped, &g_fm_cleared, &g_fm_forgotten, &g_fm_unrecorded,
                    &g_fm_max_age, &g_fm_deferred, &g_fm_age_max, &g_fm_logged, &g_fm_rel_logged,
                    &g_fm_other_logged, &g_fm_with_parent, &g_fm_after_parent, &g_fm_orphan_timeouts,
                    &g_fm_converted, &g_fm_blocked_native, &g_fm_would_block, &g_fm_held_unknown, &g_fm_held_in_call,
                    &g_fm_held_held, &g_fm_known_overflow, &g_fm_ac_same, &g_fm_ac_other, &g_fm_ac_only,
                    &g_fm_ac_logged, &g_fm_tail_calls, &g_out_records, &g_out_orphans, &g_out_2005, &g_out_2516,
                    &g_out_2174,
                    &g_out_logged}) {
        c->store(0);
    }
    g_pub_gate.store(0);
    g_pub_retain_ms.store(60000);
    for (auto* c : {&g_pg_evaluated, &g_pg_published, &g_pg_gone, &g_pg_would, &g_pg_retained, &g_pg_dropped_expired,
                    &g_pg_dropped_no_room, &g_pg_withheld_no_entry, &g_pg_would_no_entry, &g_pg_cc_unknown_held,
                    &g_pg_cc_unknown_would, &g_pg_retain_max_ms, &g_pg_logged, &g_pg_drop_logged, &g_pg_entry_logged,
                    &g_pg_merged, &g_pg_members_dragged, &g_pg_unchecked_sam, &g_pg_unchecked_session,
                    &g_pg_unchecked_error, &g_pg_unchecked_logged, &g_pg_shadow_recorded, &g_pg_shadow_full,
                    &g_pg_shadow_recovered, &g_pg_shadow_would_drop, &g_pg_shadow_gone, &g_pg_shadow_recover_max_ms}) {
        c->store(0);
    }
    g_pub_shadow_n = 0;
    g_pub_shadow_size.store(0);
    for (auto& c : g_pg_by_verdict) c.store(0);
    g_size = 0;
    g_npc_size = 0;
    g_char_size = 0;
    g_settle_size = 0;
    g_settle_ms.store(0);
    g_announced.clear();
    for (auto* c : {&g_settle_held, &g_settle_held_host, &g_settle_held_user2, &g_settle_again, &g_settle_full,
                    &g_settle_unrecorded, &g_settle_released, &g_settle_settled, &g_settle_max_wait, &g_settle_native,
                    &g_settle_dropped, &g_settle_cleared, &g_settle_forgotten, &g_settle_deferred, &g_settle_d53_waited,
                    &g_settle_announced, &g_settle_age_max, &g_settle_hold_logged, &g_settle_release_logged,
                    &g_settle_other_logged, &g_settle_last_pass, &g_settle_last_fallback, &g_settle_d53_logged,
                    &g_settle_raced, &g_settle_fallback}) {
        c->store(0);
    }
    for (auto& t : g_native_tids) t.store(0);
    g_thread_rule.store(false);
    g_appear_tid.store(0);
    g_defer.reset();
    for (auto* c : {&g_char_held, &g_char_held_host, &g_char_held_user2, &g_char_again, &g_char_full,
                    &g_char_unrecorded, &g_char_released, &g_char_restore1, &g_char_timeouts, &g_char_native,
                    &g_char_dropped, &g_char_cleared, &g_char_forgotten, &g_char_deferred, &g_char_not_main,
                    &g_char_age_max, &g_char_hold_logged, &g_char_release_logged, &g_char_other_logged,
                    &g_char_last_pass, &g_char_last_fallback, &g_child_tail_tick, &g_native_count, &g_native_full,
                    &g_notify_foreign, &g_child_deferred, &g_npc_thread_deferred, &g_native_logged}) {
        c->store(0);
    }
    g_characters = characters;
    for (auto* c : {&g_calls, &g_split, &g_unreadable, &g_not_realm, &g_held, &g_held_again, &g_held_host,
                    &g_held_user2, &g_unrecorded, &g_owner_sent, &g_owner_absent, &g_released, &g_dropped, &g_cleared,
                    &g_timeouts, &g_forgotten, &g_errors, &g_sweep_other, &g_action_calls, &g_hold_logged,
                    &g_release_logged, &g_other_logged, &g_npc_held, &g_npc_held_host_ctrl, &g_npc_held_user2_ctrl,
                    &g_npc_again, &g_npc_full, &g_npc_unrecorded, &g_npc_released, &g_npc_released_ctrl,
                    &g_npc_dropped, &g_npc_timeouts, &g_npc_native, &g_npc_forgotten, &g_npc_cleared,
                    &g_npc_ctrl_changed, &g_npc_release_calls, &g_npc_deferred, &g_npc_busy_skips, &g_npc_targeted,
                    &g_npc_periodic, &g_npc_evaluated, &g_npc_pass_us_sum, &g_npc_pass_us_max, &g_prepare_us_max,
                    &g_npc_hold_logged, &g_npc_release_logged, &g_npc_other_logged, &g_npc_age_sum, &g_npc_age_max,
                    &g_npc_last_pass, &g_npc_last_fallback, &g_last_tick, &g_notes_lost}) {
        c->store(0);
    }
    g_load_defer.store(0);
    g_user2_loading.store(false);
    g_load_stuck_noted.store(false);
    for (auto* c : {&g_ld_deferred, &g_ld_would, &g_ld_released, &g_ld_cap, &g_ld_dropped, &g_ld_wait_sum,
                    &g_ld_wait_max, &g_ld_kept, &g_ld_logged, &g_ld_rel_logged, &g_ld_loads, &g_ld_phase_logged,
                    &g_ld_drop_despawned, &g_ld_drop_gone, &g_ld_drop_other, &g_ld_stuck, &g_load_start_ms,
                    &g_load_end_ms}) {
        c->store(0);
    }
    p8p::Event e;
    while (g_notes.pop(e)) {
    }
    g_children = children;
    g_observers = observers;
    g_active = seams != nullptr;
}

void notify(uintptr_t flag, const GameVec* sessions, const GameVec* keys) { notify_detour(flag, sessions, keys); }

void start_action(uintptr_t ctx) {
    uint32_t key = 0;
    if (g_observers.load() && (g_npc_size.load() || g_fam_size.load())) key = start_action_req_key(ctx).value_or(0);
    after_start_action(key);
}

void server_tick() {
    if (!g_size.load() && !g_npc_size.load() && !g_char_size.load() && !g_settle_size.load() && !g_fam_size.load()) {
        return;
    }
    server_tick_body(false);
}

void set_settle_ms(uint32_t ms) { g_settle_ms.store(ms); }

void add_settle_entry(const HoldEntry& e) {
    std::lock_guard lock(g_mu);
    (void)g_settle_table.add(e);
    g_settle_size.store(g_settle_table.size());
}

size_t settle_size() {
    std::lock_guard lock(g_mu);
    return g_settle_table.size();
}

bool settle_entry(size_t i, HoldEntry& out) {
    std::lock_guard lock(g_mu);
    if (i >= g_settle_table.size()) return false;
    out = g_settle_table.at(i);
    return true;
}

SettleCounters settle_counters() {
    SettleCounters c;
    c.held = g_settle_held.load();
    c.again = g_settle_again.load();
    c.full = g_settle_full.load();
    c.released = g_settle_released.load();
    c.settled = g_settle_settled.load();
    c.max_wait = g_settle_max_wait.load();
    c.native = g_settle_native.load();
    c.dropped = g_settle_dropped.load();
    c.cleared = g_settle_cleared.load();
    c.forgotten = g_settle_forgotten.load();
    c.deferred = g_settle_deferred.load();
    c.d53_waited = g_settle_d53_waited.load();
    c.announced = g_settle_announced.load();
    c.raced = g_settle_raced.load();
    c.fallback = g_settle_fallback.load();
    return c;
}

size_t char_size() {
    std::lock_guard lock(g_mu);
    return g_char_table.size();
}

bool char_entry(size_t i, HoldEntry& out) {
    std::lock_guard lock(g_mu);
    if (i >= g_char_table.size()) return false;
    out = g_char_table.at(i);
    return true;
}

void fill_char(size_t n) {
    std::lock_guard lock(g_mu);
    for (size_t i = 0; i < n; ++i) {
        HoldEntry e;
        e.key = 0xAF000000u + static_cast<uint32_t>(i);
        e.observer = 0xF000 + i;
        e.character = true;
        e.epoch = server_epoch();
        e.since_ms = now_ms();
        if (g_char_table.add(e) == CharHoldTable::Add::Full) break;
    }
    g_char_size.store(g_char_table.size());
}

size_t child_size() {
    std::lock_guard lock(g_mu);
    return g_table.size();
}

CharCounters char_counters() {
    CharCounters c;
    c.held = g_char_held.load();
    c.again = g_char_again.load();
    c.full = g_char_full.load();
    c.released = g_char_released.load();
    c.restore1 = g_char_restore1.load();
    c.timeouts = g_char_timeouts.load();
    c.native = g_char_native.load();
    c.dropped = g_char_dropped.load();
    c.cleared = g_char_cleared.load();
    c.forgotten = g_char_forgotten.load();
    c.deferred = g_char_deferred.load();
    c.not_main = g_char_not_main.load();
    c.child_released = g_released.load();
    c.child_deferred = g_child_deferred.load();
    c.npc_deferred = g_npc_thread_deferred.load();
    c.native_threads = g_native_count.load();
    return c;
}

static std::string g_lines_buf;

void network_tick() {
    g_test_lines = &g_lines_buf;
    child_hold_network_tick();
    g_test_lines = nullptr;
}

std::string lines() {
    std::string s;
    s.swap(g_lines_buf);
    return s;
}

size_t npc_size() {
    std::lock_guard lock(g_mu);
    return g_npc_table.size();
}

size_t npc_size_atomic() { return g_npc_size.load(); }

size_t npc_reserved() {
    std::lock_guard lock(g_mu);
    return g_npc_reserved;
}

bool npc_entry(size_t i, HoldEntry& out) {
    std::lock_guard lock(g_mu);
    if (i >= g_npc_table.size()) return false;
    out = g_npc_table.at(i);
    return true;
}

void fill_npc(size_t n) {
    std::lock_guard lock(g_mu);
    for (size_t i = 0; i < n; ++i) {
        HoldEntry e;
        e.key = 0xBF000000u + static_cast<uint32_t>(i);
        e.observer = 0xF000 + i;
        e.npc = true;
        e.epoch = server_epoch();
        e.since_ms = now_ms();
        if (g_npc_table.add(e) == NpcHoldTable::Add::Full) break;
    }
    g_npc_size.store(g_npc_table.size());
}

Counters counters() {
    Counters c;
    c.held = g_npc_held.load();
    c.again = g_npc_again.load();
    c.full = g_npc_full.load();
    c.unrecorded = g_npc_unrecorded.load();
    c.released = g_npc_released.load();
    c.by_control = g_npc_released_ctrl.load();
    c.timeouts = g_npc_timeouts.load();
    c.native = g_npc_native.load();
    c.dropped = g_npc_dropped.load();
    c.deferred = g_npc_deferred.load();
    c.targeted = g_npc_targeted.load();
    c.periodic = g_npc_periodic.load();
    c.evaluated = g_npc_evaluated.load();
    return c;
}

void set_thread_rule(bool on) { g_thread_rule.store(on); }

uint64_t defer_max_ms() { return g_defer.max_ms(); }

void set_load_defer(uint8_t mode, bool user2_loading) {
    child_hold_set_load_defer(mode);
    child_hold_note_user2_loading(user2_loading);
}

void set_family(uint8_t mode) { child_hold_set_family(mode); }

size_t family_size() {
    std::lock_guard lock(g_mu);
    return g_fam_table.size();
}

bool family_entry(size_t i, HoldEntry& out) {
    std::lock_guard lock(g_mu);
    if (i >= g_fam_table.size()) return false;
    out = g_fam_table.at(i);
    return true;
}

bool family_known(uint32_t key) {
    std::lock_guard lock(g_mu);
    return g_known_session && g_known.contains(key);
}

void fill_family(size_t n) {
    std::lock_guard lock(g_mu);
    for (size_t i = 0; i < n; ++i) {
        HoldEntry e;
        e.key = 0xBE000000u + static_cast<uint32_t>(i);
        e.observer = 0xE000 + i;
        e.family = true;
        e.parent = 0xBD000000u + static_cast<uint32_t>(i);
        e.epoch = server_epoch();
        e.since_ms = now_ms();
        if (g_fam_table.add(e) == FamilyHoldTable::Add::Full) break;
    }
    g_fam_size.store(g_fam_table.size());
}

FamilyCounters family_counters() {
    FamilyCounters c;
    c.with_parent = g_fm_with_parent.load();
    c.after_parent = g_fm_after_parent.load();
    c.orphan_timeouts = g_fm_orphan_timeouts.load();
    c.converted = g_fm_converted.load();
    c.blocked_native = g_fm_blocked_native.load();
    c.would_block = g_fm_would_block.load();
    c.held_unknown = g_fm_held_unknown.load();
    c.unknown_off = g_fm_unknown_off.load();
    c.ac_same = g_fm_ac_same.load();
    c.ac_other = g_fm_ac_other.load();
    c.ac_only = g_fm_ac_only.load();
    c.out_records = g_out_records.load();
    c.out_orphans = g_out_orphans.load();
    c.seen = g_fm_seen.load();
    c.would = g_fm_would.load();
    c.held = g_fm_held.load();
    c.again = g_fm_again.load();
    c.full = g_fm_full.load();
    c.partial = g_fm_partial.load();
    c.unlinked = g_fm_unlinked.load();
    c.released = g_fm_released.load();
    c.orphans = g_fm_orphans.load();
    c.max_age = g_fm_max_age.load();
    c.dropped = g_fm_dropped.load();
    c.cleared = g_fm_cleared.load();
    c.forgotten = g_fm_forgotten.load();
    c.unrecorded = g_fm_unrecorded.load();
    c.deferred = g_fm_deferred.load();
    return c;
}

PubCounters pub_counters() {
    PubCounters c;
    c.evaluated = g_pg_evaluated.load();
    c.published = g_pg_published.load();
    c.gone = g_pg_gone.load();
    c.would = g_pg_would.load();
    c.retained = g_pg_retained.load();
    c.dropped_expired = g_pg_dropped_expired.load();
    c.dropped_no_room = g_pg_dropped_no_room.load();
    c.withheld_no_entry = g_pg_withheld_no_entry.load();
    c.would_no_entry = g_pg_would_no_entry.load();
    c.cc_unknown_held = g_pg_cc_unknown_held.load();
    c.cc_unknown_would = g_pg_cc_unknown_would.load();
    c.merged = g_pg_merged.load();
    c.members_dragged = g_pg_members_dragged.load();
    c.unchecked = g_pg_unchecked_sam.load() + g_pg_unchecked_session.load() + g_pg_unchecked_error.load();
    c.shadow_recorded = g_pg_shadow_recorded.load();
    c.shadow_recovered = g_pg_shadow_recovered.load();
    c.shadow_would_drop = g_pg_shadow_would_drop.load();
    c.shadow_pending = g_pub_shadow_size.load();
    c.retain_max_ms = g_pg_retain_max_ms.load();
    for (size_t i = 0; i < std::size(c.by_verdict) && i < std::size(g_pg_by_verdict); ++i) {
        c.by_verdict[i] = g_pg_by_verdict[i].load();
    }
    return c;
}

LoadDeferCounters load_defer_counters() {
    LoadDeferCounters c;
    c.deferred = g_ld_deferred.load();
    c.would = g_ld_would.load();
    c.released = g_ld_released.load();
    c.released_at_cap = g_ld_cap.load();
    c.dropped = g_ld_dropped.load();
    c.dropped_despawned = g_ld_drop_despawned.load();
    c.dropped_gone = g_ld_drop_gone.load();
    c.dropped_other = g_ld_drop_other.load();
    c.stuck = g_ld_stuck.load();
    c.waited_max_ms = g_ld_wait_max.load();
    return c;
}

}  // namespace hold_test

}  // namespace cdmp::session2
