#pragma once
// P8, user 2's rank permit and the per-user owner funnels
// (docs/research/pendientes/p8-sistemas-juego.md §11.1 and §11.7; the
// implementation: docs/research/pendientes/p8-impl-rango-embudos.md): the pure
// logic of user2_funnels.cpp, with no game access, so the tests can run it.
//
// Three [session2] keys, host only, each 0 (default) | probe | 1:
//   rank_permit         A: in the host's CLIENT, vf188(5) ("this client controls
//                       it") of user 2's main character answers 1 at the two
//                       rank-permit calls 0x221E281 / 0x221F29F, so the host's
//                       enemies grant (and drop) a native rank permit on it.
//   quest_per_user      B: inside one of user 2's Req on the host's SERVER (the
//                       "subject", set at ExecuteTroc 0x2774B20), ServerField::vf40
//                       0x2B00C70 returns user 2's ServerQuestManager instead of
//                       the field owner's (the host's).
//   kill_loot_per_user  C: same scope; DeadActor 0x62 (0x2AFFF50 from 0x29432DE)
//                       and the dead body's loot recipient (0x20DEE60 from
//                       0x2B83D24) go to user 2 instead of the field owner.
// probe = count only (what would change), nothing changes.

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace cdmp::session2::u2f {

// ---------------------------------------------------------------- the option

enum class Mode : uint8_t { Off, Probe, On };

struct ParsedMode {
    Mode mode = Mode::Off;
    bool known = true;  // false: an unknown value, treated as Off (warned)
};

inline ParsedMode parse_mode(std::string_view raw) {
    while (!raw.empty() && (raw.front() == ' ' || raw.front() == '\t')) raw.remove_prefix(1);
    // An inline comment ("probe ; G1") is not part of the value.
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

// ---------------------------------------------------------------- quest_policy (docs/research/s25/politica-misiones.md)
//
// [session2] quest_policy = 0 | probe | 1 (host), independent of quest_per_user. The rules of 2026-10-13 and of
// 2026-10-14 (S34): the guest follows the HOST's quest / world progress and never advances quests of its own in the
// host's world; what it does counts for the HOST's quests, as a companion's would.
//
// The native fact this rests on (politica-misiones.md, "El compañero nativo"): every game event of a character
// (KillActor, DeadActor, interactions, zone in/out...) is handled by its ServerQuestActorComponent callback 0x290DBD0,
// which asks the FIELD's vf40 for the quest manager (return 0x290DC0B): in the host's field that is the host's. So the
// policy keeps the field owner's (the host's) manager wherever progress is made, and gives user 2 its own manager only
// where a Req of its client changes per-player UI state and expects an Ack.
//
// ServerField::vf40 callers (return RVAs), inside user 2's Req (the subject) in a field the host owns:
//   the host's (the original, counted; quest_per_user is not asked):
//     0x2B03AA7  the respawn / safe position 0x2B03A60
//     0x2C4A36F  MissionTriggerInOutReq 2112 (0x2C4A310: the event goes to [manager+0x10], the manager's character)
//     0x290DC0B  the quest component's game-event callback 0x290DBD0 (the progress of every event)
//     0x104C4B3D ChallengeDiscoverActorReq 2215 (.xtls 0x104C49F0; a return address compared, nothing hooked there)
//     0x2C3409D  StartChallengeCompleteTimerOnceTimer 2051 (0x2C34020)
//     0x2A4A32B  ChangePlayerbleCharacterReq 2369 (0x2A4A180; dropped at the ingress with 1: counted if seen)
//   user 2's own (its client gets its Ack as natively; the host's state is never touched):
//     0x2C4A0AD  UpdateTraceMissionReq 2372 (0x2C4A050), Ack 2346
//     0x2A49183  UpdateMissionUIStateListReq 2477 (0x2A48F00), Ack 2203
//     0x2A4A03B  SetMissionNewAlarmFalseReq 2354 (0x2A49F00), Ack 2212
// 0x2896347 (the fast-travel apply's quest step) is left as is (both clients send 0: it never runs).
// probe: counts what 1 would do, changes nothing (quest_per_user decides as before).
inline constexpr uint32_t kRespawnVf40Ret = 0x2B03AA7, kTraceVf40Ret = 0x2C4A0AD, kTriggerVf40Ret = 0x2C4A36F;
inline constexpr uint32_t kQuestEventVf40Ret = 0x290DC0B, kMissionUiVf40Ret = 0x2A49183,
                          kMissionAlarmVf40Ret = 0x2A4A03B, kChallengeDiscoverVf40Ret = 0x104C4B3D,
                          kChallengeTimerVf40Ret = 0x2C3409D, kChangeCharacterVf40Ret = 0x2A4A32B;
inline constexpr uint16_t kOpTraceMission = 2372, kOpMissionTrigger = 2112, kOpMissionUiState = 2477,
                          kOpMissionNewAlarm = 2354, kOpChangePlayable = 2369;
// 1.0.0.3527 [V capstone on the PE, 2026-11-05]: the same vf40 callers on this build (each found from its Troc's
// vtable slot 2), mapped to the 2976 addresses the logic speaks. The fast-travel step keeps its literal, see
// vf40_caller_allowed. No 2976 address above is a vf40 return on this build (the bytes before each were read).
struct Vf40Ret3527 {
    uint32_t native, logical;
};
inline constexpr Vf40Ret3527 kVf40Rets3527[] = {
    {0x2D9AA1C, kRespawnVf40Ret},            // 0x2D9A8F0: 13 callers, the manager's +0x68/+0x78/+0x80 hash after it
    {0x2EEE85F, kTriggerVf40Ret},            // 0x2EEE800, from the 2112 handler 0x2CD5220: events 0x11 / 0x12 after it
    {0x2B79B6B, kQuestEventVf40Ret},         // 0x2B79B30, ServerQuestActorComponent vfB0's callback
    {0xE500077, kChallengeDiscoverVf40Ret},  // .text 0xE4FFF10, the 2215 handler 0x2CD6910's jmp; compared, not hooked
    {0xE44CF57, kChallengeDiscoverVf40Ret},  // 1.0.0.3549: the same jmp reaches 0xE44CDF0, the call [rax+0x40] at the same +0x167
    {0x2ED751D, kChallengeTimerVf40Ret},     // the 2051 handler 0x2ED74A0
    {0x2EEEA20, kChangeCharacterVf40Ret},    // 0x2EEE9D0, from the 2369 handler 0x2CD5E30
    {0x2EEE59D, kTraceVf40Ret},              // 0x2EEE540, from the 2372 handler 0x2CD4F60
    {0x2CD4CB3, kMissionUiVf40Ret},          // the 2477 handler 0x2CD4970
    {0x2CD5CA1, kMissionAlarmVf40Ret},       // the 2354 handler 0x2CD5B60
    {0x2AF3FB2, 0x2896347},                  // the fast-travel apply 0x2AF3A40's quest step
};
inline uint32_t vf40_ret_of_3527(uint32_t rva) {
    for (const Vf40Ret3527& r : kVf40Rets3527) {
        if (r.native == rva) return r.logical;
    }
    return rva;
}
// Build 1.0.0.3576 (static, 2026-11-06; not yet run): the same callers, each its function moved whole (+0xC70; the
// fast-travel apply +0xC50) and the call at the same offset in it. The function starts come from the Trocs' vtable
// slot 2 by RTTI (2112 0x2CD5E90, 2369 0x2CD6AA0, 2372 0x2CD5BD0, 2477 0x2CD55E0, 2354 0x2CD67D0, 2051 0x2ED8110,
// 2283 0x2CEE250) or from their calls. The respawn one is a direct `call 0x2D98440` (vf40) at 0x2D9B687, like 3527's.
inline constexpr Vf40Ret3527 kVf40Rets3576[] = {
    {0x2D9B68C, kRespawnVf40Ret},            // 0x2D9B560 + 0x12C
    {0x2EEF4CF, kTriggerVf40Ret},            // 0x2EEF470, from the 2112 handler 0x2CD5E90
    {0x2B7A7DB, kQuestEventVf40Ret},         // 0x2B7A7A0 (thunk 0x2B9C660 registered by vfB0 0x2B744B0)
    {0xE3F9CC7, kChallengeDiscoverVf40Ret},  // .tls$ 0xE3F9B50 (the 2215 handler 0x2CD7580's jmp); protected code: the
                                             // call [rax+0x40] is at +0x174 here (3527 +0x167); compared, not hooked
    {0x2ED818D, kChallengeTimerVf40Ret},     // the 2051 handler 0x2ED8110
    {0x2EEF690, kChangeCharacterVf40Ret},    // 0x2EEF640, from the 2369 handler 0x2CD6AA0
    {0x2EEF20D, kTraceVf40Ret},              // 0x2EEF1B0, from the 2372 handler 0x2CD5BD0
    {0x2CD5923, kMissionUiVf40Ret},          // the 2477 handler 0x2CD55E0
    {0x2CD6911, kMissionAlarmVf40Ret},       // the 2354 handler 0x2CD67D0
    {0x2AF4C02, 0x2896347},                  // the fast-travel apply 0x2AF4690's quest step
};
inline uint32_t vf40_ret_of_3576(uint32_t rva) {
    for (const Vf40Ret3527& r : kVf40Rets3576) {
        if (r.native == rva) return r.logical;
    }
    return rva;
}
// Build 1.0.0.3663 (static, 2026-11-13; never run): the same callers, each `call [rax+0x40]` at the same offset of its
// function as in 3576, except the respawn one and the fast-travel step (their functions changed a little before the
// call). Function starts from the Trocs' vtable slot 2 by RTTI (2112 0x2D3C910, 2369 0x2D3D520, 2372 0x2D3C650, 2477
// 0x2D3C060, 2354 0x2D3D250, 2051 0x2F40530, 2215 0x2D3E000) or from their calls.
inline constexpr Vf40Ret3527 kVf40Rets3663[] = {
    {0x2E0256E, kRespawnVf40Ret},            // 0x2E02450 (13 callers, as 3527's): `call 0x2DFF2F0` (vf40) at +0x119
                                             // (3576 +0x127); mov rcx,r14 (the field) before it
    {0x2F5770F, kTriggerVf40Ret},            // 0x2F576B0 +0x5F, from the 2112 handler 0x2D3C910
    {0x2BE074B, kQuestEventVf40Ret},         // 0x2BE0710 +0x3B (thunk 0x2C021A0 registered by vfB0 0x2BDA410)
    {0xEA6E9D7, kChallengeDiscoverVf40Ret},  // 0xEA6E860 (the 2215 handler 0x2D3E000's jmp), protected code: the only
                                             // call [rax+0x40] in its first 0x300 bytes, at +0x174 as in 3576
    {0x2F405AD, kChallengeTimerVf40Ret},     // the 2051 handler 0x2F40530 +0x7D
    {0x2F578D0, kChangeCharacterVf40Ret},    // 0x2F57880 +0x50, from the 2369 handler 0x2D3D520
    {0x2F5744D, kTraceVf40Ret},              // 0x2F573F0 +0x5D, from the 2372 handler 0x2D3C650
    {0x2D3C3A3, kMissionUiVf40Ret},          // the 2477 handler 0x2D3C060 +0x343
    {0x2D3D391, kMissionAlarmVf40Ret},       // the 2354 handler 0x2D3D250 +0x141
    {0x2B58C1F, 0x2896347},                  // the fast-travel apply 0x2B586B0's quest step: its only call [rax+0x40],
                                             // +0x56F (3576 +0x572)
};
inline uint32_t vf40_ret_of_3663(uint32_t rva) {
    for (const Vf40Ret3527& r : kVf40Rets3663) {
        if (r.native == rva) return r.logical;
    }
    return rva;
}
// Measured only at the ingress (the open decision about the guest's dialog choices, politica-misiones.md).
inline constexpr uint16_t kOpQuestDialogEnd = 2342, kOpSetQuestDialog = 2857, kOpStageBranchState = 2436,
                          kOpUpdateStageChartEvent = 2591;

enum class PolicyCaller : uint8_t {
    None,
    Respawn,
    Trigger,
    QuestEvent,
    ChallengeDiscover,
    ChallengeTimer,
    ChangeCharacter,
    Trace,
    MissionUi,
    MissionAlarm,
    Count
};
inline PolicyCaller policy_caller(uint32_t ret_rva) {
    switch (ret_rva) {
        case kRespawnVf40Ret: return PolicyCaller::Respawn;
        case kTriggerVf40Ret: return PolicyCaller::Trigger;
        case kQuestEventVf40Ret: return PolicyCaller::QuestEvent;
        case kChallengeDiscoverVf40Ret: return PolicyCaller::ChallengeDiscover;
        case kChallengeTimerVf40Ret: return PolicyCaller::ChallengeTimer;
        case kChangeCharacterVf40Ret: return PolicyCaller::ChangeCharacter;
        case kTraceVf40Ret: return PolicyCaller::Trace;
        case kMissionUiVf40Ret: return PolicyCaller::MissionUi;
        case kMissionAlarmVf40Ret: return PolicyCaller::MissionAlarm;
        default: return PolicyCaller::None;
    }
}
// The callers user 2's own quest manager answers (per-player UI state with an Ack); every other one keeps the host's.
inline bool caller_answers_own(PolicyCaller c) {
    return c == PolicyCaller::Trace || c == PolicyCaller::MissionUi || c == PolicyCaller::MissionAlarm;
}
inline const char* policy_caller_name(PolicyCaller c) {
    switch (c) {
        case PolicyCaller::None: return "other";
        case PolicyCaller::Respawn: return "respawn point 0x2B03AA7";
        case PolicyCaller::Trigger: return "2112 zone 0x2C4A36F";
        case PolicyCaller::QuestEvent: return "game events 0x290DC0B";
        case PolicyCaller::ChallengeDiscover: return "2215 challenge discover 0x104C4B3D";
        case PolicyCaller::ChallengeTimer: return "2051 challenge timer 0x2C3409D";
        case PolicyCaller::ChangeCharacter: return "2369 change character 0x2A4A32B";
        case PolicyCaller::Trace: return "2372 trace 0x2C4A0AD";
        case PolicyCaller::MissionUi: return "2477 mission UI 0x2A49183";
        case PolicyCaller::MissionAlarm: return "2354 new alarm 0x2A4A03B";
        default: return "?";
    }
}

enum class PolicyOut : uint8_t {
    None,           // not one of the policy's callers, or off, or not the host's field: quest_per_user decides
    HostKept,       // 1: the original (the host's quest manager), quest_per_user skipped
    HostWould,      // probe: would be the host's
    OwnAnswered,    // 1: user 2's own quest manager
    OwnWould,       // probe: would be user 2's own
    OwnUnreadable,  // 1: its own unreadable (the ingress should have dropped the Req): quest_per_user / the original, ERR
    Count
};
inline PolicyOut decide_quest_policy(Mode policy, PolicyCaller caller, bool host_field, bool mine_ok) {
    if (policy == Mode::Off || !host_field || caller == PolicyCaller::None || caller == PolicyCaller::Count) {
        return PolicyOut::None;
    }
    if (caller_answers_own(caller)) {
        if (policy == Mode::Probe) return PolicyOut::OwnWould;
        return mine_ok ? PolicyOut::OwnAnswered : PolicyOut::OwnUnreadable;
    }
    return policy == Mode::On ? PolicyOut::HostKept : PolicyOut::HostWould;
}
inline PolicyOut decide_quest_policy(Mode policy, uint32_t ret_rva, bool host_field, bool mine_ok) {
    return decide_quest_policy(policy, policy_caller(ret_rva), host_field, mine_ok);
}
// The tunnel's ingress: can user 2's Req only reach ITS OWN quest manager? (review of 7da4dfa, M1)
enum class RouteFail : uint8_t {
    None,          // the vf40 detour will see the subject and answer its own quest manager
    NotLive,       // the subject / vf40 hooks are not in (the original would answer: the owner's)
    KeysNotLive,   // the keys are not live yet (refreshed every 100 ms after a login / reload): no subject
    NotItsChar,    // the session's main character is not the one the keys name, or fails the subject test (key,
                   // controller +0x90, class: decide_subject, as subject_enter at ExecuteTroc): no subject
    OwnUnreadable, // its own quest manager cannot be read
    Count
};
struct RouteIn {
    bool vf40_live = false;  // checked first: the vtables it needs are published before (g_on, seq_cst)
    bool keys_live = false;
    uint32_t char_key = 0, user2_char = 0;
    bool subject_ok = false;  // decide_subject on that character now == Subject
    bool own_ok = false;
};
inline RouteFail trace_route(const RouteIn& in) {
    if (!in.vf40_live) return RouteFail::NotLive;
    if (!in.keys_live) return RouteFail::KeysNotLive;
    if (!in.char_key || in.char_key != in.user2_char || !in.subject_ok) return RouteFail::NotItsChar;
    return in.own_ok ? RouteFail::None : RouteFail::OwnUnreadable;
}
inline const char* route_fail_name(RouteFail f) {
    switch (f) {
        case RouteFail::None: return "its own quest manager answers";
        case RouteFail::NotLive: return "the subject / vf40 hooks are not in";
        case RouteFail::KeysNotLive: return "the keys are not live yet";
        case RouteFail::NotItsChar: return "the session's character is not user 2's main one";
        case RouteFail::OwnUnreadable: return "its own quest manager cannot be read";
        default: return "?";
    }
}
// The Reqs whose vf40 user 2's own quest manager answers (2372, 2477, 2354): judged by their route at the ingress.
inline bool policy_own_req(uint16_t opcode) {
    return opcode == kOpTraceMission || opcode == kOpMissionUiState || opcode == kOpMissionNewAlarm;
}
// The Reqs the ingress only counts (dialogs and stage choices of user 2: never dropped, the open decision).
inline bool policy_measured_req(uint16_t opcode) {
    return opcode == kOpQuestDialogEnd || opcode == kOpSetQuestDialog || opcode == kOpStageBranchState ||
           opcode == kOpUpdateStageChartEvent;
}
// Every Req the ingress looks at with quest_policy on.
inline bool policy_relevant_req(uint16_t opcode) {
    return opcode == kOpMissionTrigger || opcode == kOpChangePlayable || policy_own_req(opcode) ||
           policy_measured_req(opcode);
}
// 1, outside a field of user 2's own (there the field's owner IS user 2: natively its own):
//   - 2372 / 2477 / 2354 are dropped unless they can only reach its own quest manager;
//   - 2369 ChangePlayerbleCharacterReq is always dropped (a reload trip, and its vf40 is the host's quest manager).
// The cheats 2627 / 2251 never get here: the tunnel blocks every *Cheat* Req (server.cpp).
inline bool policy_drops_req(Mode policy, uint16_t opcode, RouteFail route, bool own_field) {
    if (policy != Mode::On || own_field) return false;
    if (opcode == kOpChangePlayable) return true;
    return policy_own_req(opcode) && route != RouteFail::None;
}
// What probe counts as "1 would drop it".
inline bool policy_would_drop_req(Mode policy, uint16_t opcode, RouteFail route, bool own_field) {
    return policy == Mode::Probe && policy_drops_req(Mode::On, opcode, route, own_field);
}
inline const char* policy_out_name(PolicyOut o) {
    switch (o) {
        case PolicyOut::None: return "none";
        case PolicyOut::HostKept: return "the host's";
        case PolicyOut::HostWould: return "would be the host's";
        case PolicyOut::OwnAnswered: return "its own";
        case PolicyOut::OwnWould: return "would be its own";
        case PolicyOut::OwnUnreadable: return "its own unreadable (ERR)";
        default: return "?";
    }
}
// quest_per_user's substitution of vf40 at a caller: never at a caller the policy keeps for the host with 1.
inline bool quest_per_user_may_substitute(Mode policy, PolicyCaller caller) {
    return !(policy == Mode::On && caller != PolicyCaller::None && caller != PolicyCaller::Count &&
             !caller_answers_own(caller));
}
// DeadActor (kill_loot_per_user's 0x2AFFF50 from 0x29432DE): with quest_policy=1 it stays native (the field owner's
// character), the camp / kill counters being quest progress; the loot recipient stays per user.
inline bool policy_keeps_dead_native(Mode policy) { return policy == Mode::On; }

// The probe at the quest component's event callback 0x290DBD0(component, event): the event's type byte +8 and its
// actor key +0x68, for the events of user 2's character ([component+8]).
inline constexpr uint32_t kQuestCompActor = 0x08, kEventType = 0x08, kEventActorKey = 0x68;
enum class EventActor : uint8_t { User2, Host, Other, Zero, Count };
inline EventActor classify_event_actor(uint32_t key, uint32_t user2_char, uint32_t host_char) {
    if (!key) return EventActor::Zero;
    if (key == user2_char) return EventActor::User2;
    if (host_char && key == host_char) return EventActor::Host;
    return EventActor::Other;
}
// The host client's quest Acks the probe counts (sniffer, S>C).
inline constexpr uint16_t kAckHostQuest[] = {3009, 3088, 2738, 2346};
inline int host_quest_ack_index(uint16_t op) {
    for (int i = 0; i < 4; ++i) {
        if (kAckHostQuest[i] == op) return i;
    }
    return -1;
}

// ---------------------------------------------------------------- keys

// Actor keys: class in the top nibble (users 0x9, main characters 0xA, NPCs and
// children 0xB; identity_fix.h kCharacterClass).
inline bool is_user_key(uint32_t k) { return k != 0 && (k >> 28) == 0x9; }
inline bool is_character_key(uint32_t k) { return k != 0 && (k >> 28) == 0xA; }

// What the mod's thread publishes every 100 ms (atomics; the hooks read a copy).
struct Keys {
    bool live = false;        // user 2 is logged in (server_user2_present)
    uint32_t user2_user = 0;  // its user key (MainUserDataStartAck), 0x9...
    uint32_t user2_char = 0;  // its main character's key (MainPlayerDataStartAck), 0xA...
    uint32_t host_user = 0;   // the host's user key (session 1's ServerUserActor +0x60), 0x9...
};

// A needs user 2's two keys; B/C need user 2's and the host's user keys, distinct.
inline bool keys_for_rank(const Keys& k) {
    return k.live && is_user_key(k.user2_user) && is_character_key(k.user2_char);
}
inline bool keys_for_funnels(const Keys& k) {
    return k.live && is_user_key(k.user2_user) && is_user_key(k.host_user) && k.user2_user != k.host_user;
}

// An actor (the host's client or server) is user 2's MAIN character: its key is
// the one of user 2's MainPlayerDataStartAck and its controller [actor+0x90] is
// user 2's user key. Both nonzero.
inline bool is_user2_character(const Keys& k, uint32_t actor_key, uint32_t controller) {
    return is_character_key(k.user2_char) && is_user_key(k.user2_user) && actor_key == k.user2_char &&
           controller == k.user2_user;
}

// ---------------------------------------------------------------- A: the rank permit (host's client)

// 0x221E281 / 0x221F29F: `call [rax+0x188]` with dl = 5, rcx = X (the target).
// The thunk always calls the original; then this decides what the caller gets.
struct RankIn {
    Mode mode = Mode::Off;
    Keys keys;
    uint8_t arg = 0;          // dl
    bool read_ok = false;     // X's key and controller were readable
    uint32_t key = 0;         // u32 [X+0x60]
    uint32_t controller = 0;  // u32 [X+0x90]
    bool orig = false;        // what vf188 answered
    bool target_comp = false; // [[X+0x68]+0x90] (X's target component, C_X) is not null
};

enum class RankOut : uint8_t {
    Pass,      // off, not live, an unexpected argument, X unreadable: the original
    NotUser2,  // X is not user 2's main character: the original
    OrigTrue,  // user 2's character and the original already says 1
    Would,     // probe: would answer 1 (the original said 0)
    NoComp,    // 1: would answer 1 but X has no target component (0x221E2B4 would pass null): the original
    Override,  // 1: answers 1 instead of 0
};

struct RankDecision {
    RankOut what = RankOut::Pass;
    bool result = false;
    bool user2 = false;  // X is user 2's character (counted as "reached")
};

inline RankDecision decide_rank(const RankIn& in) {
    RankDecision d;
    d.result = in.orig;
    if (in.mode == Mode::Off || in.arg != 5 || !keys_for_rank(in.keys) || !in.read_ok) return d;
    if (!is_user2_character(in.keys, in.key, in.controller)) {
        d.what = RankOut::NotUser2;
        return d;
    }
    d.user2 = true;
    if (in.orig) {
        d.what = RankOut::OrigTrue;
        return d;
    }
    if (in.mode == Mode::Probe) {
        d.what = RankOut::Would;
        return d;
    }
    if (!in.target_comp) {
        d.what = RankOut::NoComp;
        return d;
    }
    d.what = RankOut::Override;
    d.result = true;
    return d;
}

inline const char* rank_out_name(RankOut o) {
    switch (o) {
        case RankOut::Pass: return "pass";
        case RankOut::NotUser2: return "not user 2";
        case RankOut::OrigTrue: return "original already 1";
        case RankOut::Would: return "would answer 1 (probe)";
        case RankOut::NoComp: return "no target component";
        case RankOut::Override: return "answered 1";
    }
    return "?";
}

// ---------------------------------------------------------------- B/C: the subject (host's server)

// ExecuteTroc 0x2774B20(int* res, Troc*, TrocParams* params): [params] = the
// sending session's character. The subject is that actor when it is user 2's
// main character: a ServerNormalInGameActor (its vtable) with user 2's keys.
struct SubjectIn {
    bool on = false;            // quest_per_user or kill_loot_per_user is probe/1
    Keys keys;
    bool params_ok = false;     // [params] read (a null pointer reads fine and gives NoActor)
    uintptr_t actor = 0;        // [params]
    bool read_ok = false;       // the actor's vtable, key and controller were readable
    uintptr_t vtable = 0;
    uintptr_t expected_vtable = 0;   // exe + 0x5B1E2B0: ServerChildOnlyInGameActor (the user's characters, [user+0xD0])
    uintptr_t expected_vtable2 = 0;  // exe + 0x5B1DE20: ServerNormalInGameActor
    uint32_t key = 0;
    uint32_t controller = 0;
};

enum class SubjectVerdict : uint8_t { Off, NotLive, NoActor, Unreadable, NotUser2, WrongClass, Subject };

inline SubjectVerdict decide_subject(const SubjectIn& in) {
    if (!in.on) return SubjectVerdict::Off;
    if (!keys_for_funnels(in.keys) || !is_character_key(in.keys.user2_char)) return SubjectVerdict::NotLive;
    if (!in.params_ok || !in.actor) return SubjectVerdict::NoActor;
    if (!in.read_ok) return SubjectVerdict::Unreadable;
    if (!is_user2_character(in.keys, in.key, in.controller)) return SubjectVerdict::NotUser2;
    if (in.vtable != in.expected_vtable && (!in.expected_vtable2 || in.vtable != in.expected_vtable2))
        return SubjectVerdict::WrongClass;
    return SubjectVerdict::Subject;
}

inline const char* subject_name(SubjectVerdict v) {
    switch (v) {
        case SubjectVerdict::Off: return "off";
        case SubjectVerdict::NotLive: return "no live user 2";
        case SubjectVerdict::NoActor: return "no actor";
        case SubjectVerdict::Unreadable: return "unreadable";
        case SubjectVerdict::NotUser2: return "not user 2";
        case SubjectVerdict::WrongClass: return "user 2's keys on another class";
        case SubjectVerdict::Subject: return "user 2";
    }
    return "?";
}

// ---------------------------------------------------------------- B/C: one funnel call

// A funnel (vf40, 0x2AFFF50, 0x20DEE60) is asked about a field; its owner is
// u32 [field+0x180]. Only the SHARED field counts: owner = the host's user. In
// user 2's own field the owner is already user 2 (the original is right).
struct FunnelIn {
    Mode mode = Mode::Off;
    bool subject = false;   // inside a Req of user 2 (this thread)
    bool caller_ok = true;  // the filtered call site (0x2AFFF50 / 0x20DEE60); vf40: always
    Keys keys;
    bool owner_ok = false;  // [field+0x180] readable
    uint32_t owner = 0;
};

enum class FunnelOut : uint8_t {
    NoSubject,   // not inside a Req of user 2: the original
    OtherCaller, // another call site: the original
    NoKeys,      // keys unknown / user 2 not live: the original
    Unreadable,  // the field's owner unreadable: the original
    OwnerUser2,  // user 2 already owns the field: the original
    OwnerOther,  // owned by neither the host nor user 2: the original
    Probe,       // probe: the original, counted as "would go to user 2"
    Substitute,  // 1: user 2's
};

// vf40 callers (return RVAs) that take user 2's quest manager: MissionTriggerInOutReq (0x2C4A36C call [rax+0x40]),
// UpdateTraceMissionReq (0x2C4A0AA) and the respawn point (0x2B03AA2). The other 13 (trip end 0x2BC76BC on the 2322
// path, revive 0x2947F76, stage functions 0x28xxxxx, .xtls) keep the owner's: counted, never changed.
// P8 session 15 (p8-impl-viaje-rapido.md §2.3): also 0x2896347, the quest step of the fast-travel apply 0x2896120
// (`call [rax+0x40]` at 0x2896344, only when the 2283's first u32 maps in the table at exe+0x6D6C1F8; both client
// senders write 0 there). It runs only for a 2283 F3 let through: the traveller is user 2, so is the quest manager.
inline bool vf40_caller_allowed(uint64_t ret_rva) {
    return ret_rva == 0x2C4A36F || ret_rva == 0x2C4A0AD || ret_rva == 0x2B03AA7 || ret_rva == 0x2896347;
}

inline FunnelOut decide_funnel(const FunnelIn& in) {
    if (!in.subject) return FunnelOut::NoSubject;
    if (!in.caller_ok) return FunnelOut::OtherCaller;
    if (!keys_for_funnels(in.keys)) return FunnelOut::NoKeys;
    if (!in.owner_ok) return FunnelOut::Unreadable;
    if (in.owner == in.keys.user2_user) return FunnelOut::OwnerUser2;
    if (in.owner != in.keys.host_user) return FunnelOut::OwnerOther;
    if (in.mode == Mode::On) return FunnelOut::Substitute;
    if (in.mode == Mode::Probe) return FunnelOut::Probe;
    return FunnelOut::NoSubject;  // off: never installed; as the original
}

inline const char* funnel_out_name(FunnelOut o) {
    switch (o) {
        case FunnelOut::NoSubject: return "no subject";
        case FunnelOut::OtherCaller: return "other caller";
        case FunnelOut::NoKeys: return "keys unknown";
        case FunnelOut::Unreadable: return "owner unreadable";
        case FunnelOut::OwnerUser2: return "user 2's own field";
        case FunnelOut::OwnerOther: return "field of another owner";
        case FunnelOut::Probe: return "would be user 2's (probe)";
        case FunnelOut::Substitute: return "user 2's";
    }
    return "?";
}

// ---------------------------------------------------------------- B: user 2's quest manager

// vf40 natively: FindUser([field+0x180]) -> [[[[u+0xD0]+0x68]+0x138]+0x18]
// (0x2B00CA2..0x2B00CB4). For the subject: [[[subject+0x68]+0x138]+0x18], each
// hop checked; the component and the manager by their vtables
// (ServerQuestActorComponent exe+0x5B1F8F8, ServerQuestManager exe+0x5B1FA48;
// p8-sistemas-juego.md §11.5). Mem: u32/ptr(addr, out) -> bool.
inline constexpr uint32_t kActorComponents = 0x68;
inline constexpr uint32_t kComponentsQuest = 0x138;  // index 0x27 (0x2A7FDAE)
inline constexpr uint32_t kQuestComponentManager = 0x18;

enum class ChainFail : uint8_t { None, Components, Component, ComponentClass, Manager, ManagerClass };

inline const char* chain_fail_name(ChainFail f) {
    switch (f) {
        case ChainFail::None: return "ok";
        case ChainFail::Components: return "no component table";
        case ChainFail::Component: return "no quest component";
        case ChainFail::ComponentClass: return "quest component of another class";
        case ChainFail::Manager: return "no quest manager";
        case ChainFail::ManagerClass: return "quest manager of another class";
    }
    return "?";
}

template <class Mem>
std::optional<uintptr_t> quest_manager_of(const Mem& m, uintptr_t actor, uintptr_t comp_vt, uintptr_t mgr_vt,
                                          ChainFail* why = nullptr) {
    auto fail = [why](ChainFail f) -> std::optional<uintptr_t> {
        if (why) *why = f;
        return std::nullopt;
    };
    uintptr_t comps = 0, comp = 0, vt = 0, mgr = 0;
    if (!actor || !m.ptr(actor + kActorComponents, comps) || !comps) return fail(ChainFail::Components);
    if (!m.ptr(comps + kComponentsQuest, comp) || !comp) return fail(ChainFail::Component);
    if (!m.ptr(comp, vt) || vt != comp_vt) return fail(ChainFail::ComponentClass);
    if (!m.ptr(comp + kQuestComponentManager, mgr) || !mgr) return fail(ChainFail::Manager);
    if (!m.ptr(mgr, vt) || vt != mgr_vt) return fail(ChainFail::ManagerClass);
    if (why) *why = ChainFail::None;
    return mgr;
}

// ---------------------------------------------------------------- counters (lock-free, fixed size)

// Per-opcode counts of the Reqs under which a funnel was reached (the Troc's
// u16 opcode +0x0C; 0 = not from the handler table). Relaxed atomics only.
inline constexpr size_t kOpcodes = 4096;

class OpCounts {
public:
    void add(uint16_t op) {
        c_[op < kOpcodes ? op : 0].fetch_add(1, std::memory_order_relaxed);
    }
    uint32_t at(uint16_t op) const { return c_[op < kOpcodes ? op : 0].load(std::memory_order_relaxed); }
    // The `k` largest nonzero counts, largest first (ties: lower opcode first).
    std::vector<std::pair<uint16_t, uint32_t>> top(size_t k) const {
        std::vector<std::pair<uint16_t, uint32_t>> v;
        for (size_t i = 0; i < kOpcodes; ++i) {
            const uint32_t n = c_[i].load(std::memory_order_relaxed);
            if (n) v.emplace_back(static_cast<uint16_t>(i), n);
        }
        std::stable_sort(v.begin(), v.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
        if (v.size() > k) v.resize(k);
        return v;
    }

private:
    std::array<std::atomic<uint32_t>, kOpcodes> c_{};
};

// Per-call-site counts (return RVA): a fixed open-addressing table; a site
// that finds no free slot goes to `overflow`. Claims a slot with one CAS.
template <size_t N>
class SiteCounts {
    static_assert(N >= 2 && (N & (N - 1)) == 0, "N must be a power of two");

public:
    void add(uint32_t rva) {
        if (!rva) {
            overflow_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        size_t i = (rva * 2654435761u) & (N - 1);
        for (size_t probe = 0; probe < N; ++probe, i = (i + 1) & (N - 1)) {
            uint32_t k = key_[i].load(std::memory_order_acquire);
            if (k == 0 && key_[i].compare_exchange_strong(k, rva, std::memory_order_acq_rel)) k = rva;
            if (k == rva) {
                n_[i].fetch_add(1, std::memory_order_relaxed);
                return;
            }
        }
        overflow_.fetch_add(1, std::memory_order_relaxed);
    }
    // Every claimed site, largest count first.
    std::vector<std::pair<uint32_t, uint64_t>> rows() const {
        std::vector<std::pair<uint32_t, uint64_t>> v;
        for (size_t i = 0; i < N; ++i) {
            const uint32_t k = key_[i].load(std::memory_order_acquire);
            if (k) v.emplace_back(k, n_[i].load(std::memory_order_relaxed));
        }
        std::stable_sort(v.begin(), v.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
        return v;
    }
    uint64_t overflow() const { return overflow_.load(std::memory_order_relaxed); }

private:
    std::array<std::atomic<uint32_t>, N> key_{};
    std::array<std::atomic<uint64_t>, N> n_{};
    std::atomic<uint64_t> overflow_{0};
};

// The per-funnel ledger the summary prints.
enum Funnel : uint8_t { kVf40 = 0, kVf48 = 1, kFindUser = 2, kDead = 3, kLoot = 4, kFunnels = 5 };

inline const char* funnel_name(uint8_t f) {
    switch (f) {
        case kVf40: return "vf40 0x2B00C70 (quest manager)";
        case kVf48: return "vf48 0x2B00CE0 (sequencer manager, count only)";
        case kFindUser: return "FindUser 0x2A82590 (count only)";
        case kDead: return "0x2AFFF50 from 0x29432DE (DeadActor 0x62)";
        case kLoot: return "0x20DEE60 from 0x2B83D24 (loot recipient)";
    }
    return "?";
}

// Per funnel: calls under the subject, and how each was decided.
struct FunnelCounters {
    std::atomic<uint64_t> calls{0};          // every call (vf40/vf48/FindUser: only under a subject)
    std::atomic<uint64_t> under_subject{0};  // inside a Req of user 2
    std::array<std::atomic<uint64_t>, 8> out{};  // by FunnelOut
    std::atomic<uint64_t> same{0}, differ{0};    // probe: the original vs user 2's
    std::atomic<uint64_t> unreadable{0};         // user 2's value could not be built: the original
    OpCounts ops;                                // the Req opcodes under the subject
};

}  // namespace cdmp::session2::u2f
