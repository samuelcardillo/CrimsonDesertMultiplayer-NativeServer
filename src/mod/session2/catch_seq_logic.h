#pragma once
// P8 session 25, grabs (finishers and takedowns) by the OTHER player (docs/research/s25/finisher-sigilo.md §2.2, §4):
// the pure logic of catch_seq.cpp, with no game access, so the tests can run it. Builds 1.0.0.2976 and 1.0.0.3527
// (the addresses named below are 2976's; 3527's table follows them).
//
// The fault [V, S25 captures]: a grab is a catch frame event. The server answers both clients with
// CatchActionResultAck 2156; the client that CONTROLS the victim applies it and launches the victim's paired action
// (StartActionReq with the 2156's action and parent = grabber, plus two ChangeAIStateReq). The client applies it in
// ClientCatch_ApplyResult 0x935DD0, whose ONLY caller is the 2156 handler 0xB582B0 (call at 0xB58943). With the
// packet's flag c8 != 0 (argument 17; 1 in all 20 grabs of S25), it first compares the packet's sequence byte
// (argument 20, the 2156's last byte) with the grabber's current action sequence ON THAT CLIENT:
//   0x935E74  mov rax,[rbp+0xCF] ; movzx edx,byte [rax]            (argument 20)
//   0x935E7E  rax=[r15+8] ; rcx=[rax+0x68] ; rax=[rcx+0x40] ; rcx=[rax+0x48]   (r15 = comp, [comp+8] = grabber)
//   0x935E8E  cmp [rcx+0x93],dl ; jz apply        else: (dl == comp+0x6C -> comp+0x68 = 0) and RETURN, silently
// The sequence is byte +0x3C of the grabber's StartActionReq (20/20 grabs), and the server relays StartActionAcks
// with that byte at 0 (2,684/2,684). So on the host's client the guest's character never holds the 2156's sequence:
// the check fails, and the victim (the host client's) is never grabbed (0/9 guest grabs vs 11/11 of the host's).
//
// [session2] catch_seq = 0 (default) | probe | 1, HOST only. An inline hook at the ENTRY of 0x935DD0:
//   probe  every call logged and counted: grabber / victim keys, who controls each (byte [actor+0xC8], vf188(5)),
//          c8, the packet's sequence, the grabber's byte [[[[comp+8]+0x68]+0x40]+0x48]+0x93, match or not, the
//          return address. Also for the host's own grabs (one-PC check: there they must match).
//   1      the same, and ONLY when the grabber is not controlled here, the victim is, c8 != 0 and both bytes were
//          read: the grabber's byte is written into argument 20 (a local of the handler, read by that comparison
//          alone), so the native code goes on as for a local grabber. Anything unreadable: passed through, counted.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "mod/session2/user2_funnels_logic.h"

namespace cdmp::session2::csq {

using u2f::Mode;
using u2f::mode_name;
using u2f::parse_mode;

// ---------------------------------------------------------------- build 1.0.0.2976 (finisher-sigilo.md §2.2, §4.1)

// ClientCatch_ApplyResult: entry and its first 7 whole instructions (decomp/disasm of 0x935DD0):
//   48 89 5C 24 08 mov [rsp+8],rbx | 48 89 74 24 10 mov [rsp+0x10],rsi | 48 89 7C 24 18 mov [rsp+0x18],rdi |
//   4C 89 4C 24 20 mov [rsp+0x20],r9 | 55 push rbp | 41 54 push r12 | 41 55 push r13. No RIP-relative operand.
inline constexpr uintptr_t kApply = 0x935DD0;
inline constexpr uint8_t kApplyHead[25] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x48, 0x89, 0x7C,
                                           0x24, 0x18, 0x4C, 0x89, 0x4C, 0x24, 0x20, 0x55, 0x41, 0x54, 0x41, 0x55};
inline constexpr uint32_t kApplyBoundaries[] = {5, 10, 15, 20, 21, 23, 25};  // whole instructions of kApplyHead
// Its only caller (xrefs): CatchActionResultAck::vf2 0xB582B0 + 0x693, `call 0x935DD0`; returns to 0xB58948.
inline constexpr uintptr_t kApplyCall = 0xB58943;
inline constexpr uint8_t kApplyCallBytes[5] = {0xE8, 0x88, 0xD4, 0xDD, 0xFF};
inline constexpr uintptr_t kApplyReturn = 0xB58948;
// The check this module mirrors, read-only (verified at install; never patched): 0x935E43 .. 0x935E9A.
inline constexpr uintptr_t kCheckSite = 0x935E43;
inline constexpr uint8_t kCheckSiteBytes[] = {
    0x4C, 0x8B, 0xAD, 0xB7, 0x00, 0x00, 0x00,  // 0x935E43 mov r13,[rbp+0xB7]      (argument 17: &c8)
    0x41, 0x80, 0x7D, 0x00, 0x00,              // 0x935E4A cmp byte [r13],0
    0x0F, 0x84, 0x4D, 0x01, 0x00, 0x00,        // 0x935E4F jz 0x935FA2               (c8 == 0: no check)
    0x49, 0x8B, 0x47, 0x08,                    // 0x935E55 mov rax,[r15+8]
    0x48, 0x8D, 0x50, 0x08,                    // 0x935E59 lea rdx,[rax+8]
    0x48, 0x85, 0xC0,                          // 0x935E5D test rax,rax
    0x48, 0x0F, 0x44, 0xD7,                    // 0x935E60 cmovz rdx,rdi
    0x41, 0xB0, 0x01,                          // 0x935E64 mov r8b,1
    0x48, 0x8B, 0x12,                          // 0x935E67 mov rdx,[rdx]
    0x48, 0x8D, 0x4D, 0xAF,                    // 0x935E6A lea rcx,[rbp-0x51]
    0xE8, 0xDD, 0xD7, 0xA5, 0xFF,              // 0x935E6E call 0x393650 (Actor_Lock of the grabber)
    0x90,                                      // 0x935E73 nop
    0x48, 0x8B, 0x85, 0xCF, 0x00, 0x00, 0x00,  // 0x935E74 mov rax,[rbp+0xCF]      (argument 20: &seq)
    0x0F, 0xB6, 0x10,                          // 0x935E7B movzx edx,byte [rax]
    0x49, 0x8B, 0x47, 0x08,                    // 0x935E7E mov rax,[r15+8]          grabber = [comp+8]
    0x48, 0x8B, 0x48, 0x68,                    // 0x935E82 mov rcx,[rax+0x68]       its components
    0x48, 0x8B, 0x41, 0x40,                    // 0x935E86 mov rax,[rcx+0x40]       CharacterControl (CC)
    0x48, 0x8B, 0x48, 0x48,                    // 0x935E8A mov rcx,[rax+0x48]
    0x38, 0x91, 0x93, 0x00, 0x00, 0x00,        // 0x935E8E cmp [rcx+0x93],dl
    0x0F, 0x84, 0xC8, 0x00, 0x00, 0x00,        // 0x935E94 jz 0x935F62               (equal: the catch applies)
};
inline constexpr size_t kCheckCmpAt = 0x935E8E - kCheckSite;  // the cmp inside kCheckSiteBytes

// ---------------------------------------------------------------- build 1.0.0.3527 [V capstone on the installed PE]
// CatchActionResultAck vtable 0x5999BF8 slot 2 = handler 0xC64EB0, whose only such call is 0xC6554B `call 0xA241B0`
// (20 arguments, the same frame: arg 3 [rbp-0x3C] the victim, arg 17 [rbp-0x50] the sixth u8, arg 20 [rbp+0x90] the
// packet's last u8, parsed in the same order). 0xA241B0 has one caller, the same 25-byte head (kApplyHead) and the same
// prologue, so [rbp+0xB7] / [rbp+0xCF] are still arguments 17 / 20; [rbp+0xCF] is read at 0xA24254 only. Only the rel32 of
// the lock call differs in the check. Same chain and fields: 0xA2425E..0xA2426E, 0xA2427A..0xA24280, vf188 0x5AEEA0
// (`[actor+0xC8] != 0` for 5) called with 5 at 0x226CEE4. Captures: StartActionAck +0x3C is still 0 (127 / 127 of player
// characters in host_20261105-070654) while the Req's byte varies.
inline constexpr uintptr_t kApply3527 = 0xA241B0;
inline constexpr uintptr_t kApplyCall3527 = 0xC6554B;
inline constexpr uint8_t kApplyCallBytes3527[5] = {0xE8, 0x60, 0xEC, 0xDB, 0xFF};
inline constexpr uintptr_t kApplyReturn3527 = 0xC65550;
inline constexpr uintptr_t kCheckSite3527 = 0xA24223;
inline constexpr uint8_t kCheckSiteBytes3527[] = {
    0x4C, 0x8B, 0xAD, 0xB7, 0x00, 0x00, 0x00,  // 0xA24223 mov r13,[rbp+0xB7]      (argument 17: &c8)
    0x41, 0x80, 0x7D, 0x00, 0x00,              // 0xA2422A cmp byte [r13],0
    0x0F, 0x84, 0x4D, 0x01, 0x00, 0x00,        // 0xA2422F jz 0xA24382               (c8 == 0: no check)
    0x49, 0x8B, 0x47, 0x08,                    // 0xA24235 mov rax,[r15+8]
    0x48, 0x8D, 0x50, 0x08,                    // 0xA24239 lea rdx,[rax+8]
    0x48, 0x85, 0xC0,                          // 0xA2423D test rax,rax
    0x48, 0x0F, 0x44, 0xD7,                    // 0xA24240 cmovz rdx,rdi
    0x41, 0xB0, 0x01,                          // 0xA24244 mov r8b,1
    0x48, 0x8B, 0x12,                          // 0xA24247 mov rdx,[rdx]
    0x48, 0x8D, 0x4D, 0xAF,                    // 0xA2424A lea rcx,[rbp-0x51]
    0xE8, 0xDD, 0xF6, 0x9B, 0xFF,              // 0xA2424E call 0x3E3930 (Actor_Lock of the grabber)
    0x90,                                      // 0xA24253 nop
    0x48, 0x8B, 0x85, 0xCF, 0x00, 0x00, 0x00,  // 0xA24254 mov rax,[rbp+0xCF]      (argument 20: &seq)
    0x0F, 0xB6, 0x10,                          // 0xA2425B movzx edx,byte [rax]
    0x49, 0x8B, 0x47, 0x08,                    // 0xA2425E mov rax,[r15+8]          grabber = [comp+8]
    0x48, 0x8B, 0x48, 0x68,                    // 0xA24262 mov rcx,[rax+0x68]       its components
    0x48, 0x8B, 0x41, 0x40,                    // 0xA24266 mov rax,[rcx+0x40]       CharacterControl (CC)
    0x48, 0x8B, 0x48, 0x48,                    // 0xA2426A mov rcx,[rax+0x48]
    0x38, 0x91, 0x93, 0x00, 0x00, 0x00,        // 0xA2426E cmp [rcx+0x93],dl
    0x0F, 0x84, 0xC8, 0x00, 0x00, 0x00,        // 0xA24274 jz 0xA24342               (equal: the catch applies)
};

// ---------------------------------------------------------------- build 1.0.0.3576 (static, 2026-11-06; not yet run)
// CatchActionResultAck vtable 0x5999BF8 -> 0x599BD10 (RTTI map), slot 2 = handler 0xC64EB0 -> 0xC652D0 (+0x420); its
// call 0xC6554B -> 0xC6596B (new rel32) goes to 0xA241B0 -> 0xA24400 (+0x250), the only E8 caller of it in the code
// section, with the same 25-byte head. The check 0xA24223 -> 0xA24473: only the lock call's rel32 differs (0x3E3930 ->
// 0x3E3C10, +0x2E0); its two jz stay inside the function. Code section end 0x5597000.
inline constexpr uintptr_t kApply3576 = 0xA24400;
inline constexpr uintptr_t kApplyCall3576 = 0xC6596B;
inline constexpr uint8_t kApplyCallBytes3576[5] = {0xE8, 0x90, 0xEA, 0xDB, 0xFF};  // 0xC6596B: call 0xA24400
inline constexpr uintptr_t kApplyReturn3576 = 0xC65970;
inline constexpr uintptr_t kCheckSite3576 = 0xA24473;
inline constexpr uint8_t kCheckSiteBytes3576[] = {  // 0xA24473
    0x4C, 0x8B, 0xAD, 0xB7, 0x00, 0x00, 0x00, 0x41, 0x80, 0x7D, 0x00, 0x00, 0x0F, 0x84, 0x4D, 0x01, 0x00, 0x00,
    0x49, 0x8B, 0x47, 0x08, 0x48, 0x8D, 0x50, 0x08, 0x48, 0x85, 0xC0, 0x48, 0x0F, 0x44, 0xD7, 0x41, 0xB0, 0x01,
    0x48, 0x8B, 0x12, 0x48, 0x8D, 0x4D, 0xAF, 0xE8, 0x6D, 0xF7, 0x9B, 0xFF, 0x90, 0x48, 0x8B, 0x85, 0xCF, 0x00,
    0x00, 0x00, 0x0F, 0xB6, 0x10, 0x49, 0x8B, 0x47, 0x08, 0x48, 0x8B, 0x48, 0x68, 0x48, 0x8B, 0x41, 0x40, 0x48,
    0x8B, 0x48, 0x48, 0x38, 0x91, 0x93, 0x00, 0x00, 0x00, 0x0F, 0x84, 0xC8, 0x00, 0x00, 0x00};
static_assert(sizeof kCheckSiteBytes3576 == sizeof kCheckSiteBytes3527);

// ---------------------------------------------------------------- build 1.0.0.3663 (static, 2026-11-13; never run)
// CatchActionResultAck vtable 0x599BD10 -> 0x5A17778 (vtable_map_3576_3663.json), slot 2 = handler 0xC9D670 (3527's
// 0xC64EB0 + 0x387C0); its call at +0x69B as on 3527, 0xC9DD0B (new rel32), goes to 0xA548B0 (3527's 0xA241B0 + 0x30700),
// the only rel32 caller of it in the executable sections, with the same 25-byte head. The check at +0x73 as on 3527,
// 0xA54923: only the lock call's rel32 differs (to 0x3E4BA0, the Actor_Lock MoveField also calls); its two jz stay inside
// the function, and the fields after it (comp +0x68 / +0x6C) are read as on 3527. vf188 of ClientChildOnlyInGameActor
// 0x5990BF0 / ClientNormalInGameActor 0x5991108 is 0x5DABF0: `[rcx+0xC8] != 0` for 5 (kActor_Control unchanged). Code
// section end 0x5613000 (R-X section 0x1000 + 0x5612000).
inline constexpr uintptr_t kApply3663 = 0xA548B0;
inline constexpr uintptr_t kApplyCall3663 = 0xC9DD0B;
inline constexpr uint8_t kApplyCallBytes3663[5] = {0xE8, 0xA0, 0x6B, 0xDB, 0xFF};  // 0xC9DD0B: call 0xA548B0
inline constexpr uintptr_t kApplyReturn3663 = 0xC9DD10;
inline constexpr uintptr_t kCheckSite3663 = 0xA54923;
inline constexpr uint8_t kCheckSiteBytes3663[] = {  // 0xA54923
    0x4C, 0x8B, 0xAD, 0xB7, 0x00, 0x00, 0x00, 0x41, 0x80, 0x7D, 0x00, 0x00, 0x0F, 0x84, 0x4D, 0x01, 0x00, 0x00,
    0x49, 0x8B, 0x47, 0x08, 0x48, 0x8D, 0x50, 0x08, 0x48, 0x85, 0xC0, 0x48, 0x0F, 0x44, 0xD7, 0x41, 0xB0, 0x01,
    0x48, 0x8B, 0x12, 0x48, 0x8D, 0x4D, 0xAF, 0xE8, 0x4D, 0x02, 0x99, 0xFF, 0x90, 0x48, 0x8B, 0x85, 0xCF, 0x00,
    0x00, 0x00, 0x0F, 0xB6, 0x10, 0x49, 0x8B, 0x47, 0x08, 0x48, 0x8B, 0x48, 0x68, 0x48, 0x8B, 0x41, 0x40, 0x48,
    0x8B, 0x48, 0x48, 0x38, 0x91, 0x93, 0x00, 0x00, 0x00, 0x0F, 0x84, 0xC8, 0x00, 0x00, 0x00};
static_assert(sizeof kCheckSiteBytes3663 == sizeof kCheckSiteBytes3527);

// The chain the comparison reads (the same hops as 0x935E7E..0x935E8E; the same in 3527).
inline constexpr uint32_t kComp_Owner = 0x08;      // ClientCatchActorComponent -> its actor (the grabber)
inline constexpr uint32_t kActor_Comps = 0x68;     // actor -> component table
inline constexpr uint32_t kComps_Control = 0x40;   // -> ClientCharacterControlActorComponent (CC)
inline constexpr uint32_t kControl_Action = 0x48;  // CC -> the object whose +0x93 is compared
inline constexpr uint32_t kAction_Seq = 0x93;      // u8
// Other fields, logged only.
inline constexpr uint32_t kActor_Key = 0x60;        // u32 actor key
inline constexpr uint32_t kActor_Control = 0xC8;    // u8: vf188(5) = this client controls it (0x4FA620)
inline constexpr uint32_t kComp_Pending = 0x68;     // u32, zeroed by the failure branch when seq == comp+0x6C
inline constexpr uint32_t kComp_PendingSeq = 0x6C;  // u8
// The arguments (x64: argument N >= 5 at [entry rsp + 8 * N]): 3 = &victim key, 17 = &c8, 20 = &seq.
inline constexpr int kArgC8 = 17, kArgSeq = 20;

// ---------------------------------------------------------------- the decision

struct Inputs {
    bool c8_ok = false;
    uint8_t c8 = 0;
    bool seq_ok = false;
    uint8_t seq = 0;          // the packet's sequence byte (argument 20)
    bool grabber_ok = false;  // the grabber's byte [actor+0xC8] was read
    uint8_t grabber_ctl = 0;
    bool b_ok = false;        // the grabber's [[[[comp+8]+0x68]+0x40]+0x48]+0x93 was read
    uint8_t b = 0;
    bool victim_ok = false;   // the victim was found by its key and its byte [actor+0xC8] read
    uint8_t victim_ctl = 0;
};

enum class Verdict : uint8_t {
    Unreadable,         // c8, the packet's sequence, the grabber or its byte unreadable: passed through
    NoCheck,            // c8 == 0: the native code does not compare at all
    LocalMatch,         // the grabber is controlled here and the bytes match (the host's own grabs)
    LocalMismatch,      // the grabber is controlled here and they differ (the native code drops it)
    RemoteMatch,        // a remote grabber whose byte already matches
    RemoteVictimUnknown,  // a remote grabber, mismatch, the victim not found / its control byte unreadable
    RemoteVictimNotOurs,  // a remote grabber, mismatch, the victim is not controlled here either
    RemoteFix,          // a remote grabber, mismatch, the victim is ours: rewritten (1) or would be (probe)
    Count
};

inline const char* verdict_name(Verdict v) {
    switch (v) {
        case Verdict::Unreadable: return "UNREADABLE (passed through)";
        case Verdict::NoCheck: return "no check (c8 0)";
        case Verdict::LocalMatch: return "grabber here, match";
        case Verdict::LocalMismatch: return "grabber here, MISMATCH (the native code drops it)";
        case Verdict::RemoteMatch: return "remote grabber, match";
        case Verdict::RemoteVictimUnknown: return "remote grabber, mismatch, victim not found here";
        case Verdict::RemoteVictimNotOurs: return "remote grabber, mismatch, victim not controlled here";
        case Verdict::RemoteFix: return "remote grabber, MISMATCH, victim ours";
        case Verdict::Count: break;
    }
    return "?";
}

struct Decision {
    Verdict verdict = Verdict::Unreadable;
    bool write = false;  // write `value` into argument 20 (mode 1 only)
    uint8_t value = 0;
};

inline Decision decide(Mode m, const Inputs& in) {
    Decision d;
    if (!in.c8_ok || !in.seq_ok) return d;  // Unreadable
    if (in.c8 == 0) {
        d.verdict = Verdict::NoCheck;
        return d;
    }
    if (!in.grabber_ok || !in.b_ok) return d;  // Unreadable
    const bool match = in.b == in.seq;
    if (in.grabber_ctl != 0) {
        d.verdict = match ? Verdict::LocalMatch : Verdict::LocalMismatch;
        return d;
    }
    if (match) {
        d.verdict = Verdict::RemoteMatch;
    } else if (!in.victim_ok) {
        d.verdict = Verdict::RemoteVictimUnknown;
    } else if (in.victim_ctl == 0) {
        d.verdict = Verdict::RemoteVictimNotOurs;
    } else {
        d.verdict = Verdict::RemoteFix;
        d.write = m == Mode::On;
        d.value = in.b;
    }
    return d;
}

inline bool is_remote(Verdict v) {
    return v == Verdict::RemoteMatch || v == Verdict::RemoteVictimUnknown || v == Verdict::RemoteVictimNotOurs ||
           v == Verdict::RemoteFix;
}
inline bool is_local(Verdict v) { return v == Verdict::LocalMatch || v == Verdict::LocalMismatch; }
inline bool is_match(Verdict v) { return v == Verdict::LocalMatch || v == Verdict::RemoteMatch; }
inline bool is_mismatch(Verdict v) { return (is_local(v) || is_remote(v)) && !is_match(v); }

// ---------------------------------------------------------------- the counters (one writer: the game's thread)

struct Tally {
    std::atomic<uint64_t> calls{0}, local{0}, remote{0}, match{0}, mismatch{0}, unreadable{0}, no_check{0},
        victim_unknown{0}, victim_not_ours{0}, fix{0}, rewritten{0}, write_failed{0}, unexpected_caller{0};
    std::atomic<uint64_t> unread_args{0}, unread_grabber{0}, unread_byte{0};

    // `wrote`: the write was attempted and succeeded (true) or failed (false); only looked at when d.write.
    void note(const Inputs& in, const Decision& d, bool wrote, bool expected_caller) {
        const auto add = [](std::atomic<uint64_t>& c) { c.fetch_add(1, std::memory_order_relaxed); };
        add(calls);
        if (!expected_caller) add(unexpected_caller);
        if (is_local(d.verdict)) add(local);
        if (is_remote(d.verdict)) add(remote);
        if (is_match(d.verdict)) add(match);
        if (is_mismatch(d.verdict)) add(mismatch);
        switch (d.verdict) {
            case Verdict::Unreadable:
                add(unreadable);
                if (!in.c8_ok || !in.seq_ok) {
                    add(unread_args);
                } else if (!in.grabber_ok) {
                    add(unread_grabber);
                } else {
                    add(unread_byte);
                }
                break;
            case Verdict::NoCheck: add(no_check); break;
            case Verdict::RemoteVictimUnknown: add(victim_unknown); break;
            case Verdict::RemoteVictimNotOurs: add(victim_not_ours); break;
            case Verdict::RemoteFix:
                add(fix);
                if (d.write) add(wrote ? rewritten : write_failed);
                break;
            default: break;
        }
    }
};

// ---------------------------------------------------------------- self-consistency of the constants (tests)

// The rel32 of `call` at `at` (5 bytes E8 xx xx xx xx) lands on `target`.
inline bool call_targets(uintptr_t at, const uint8_t (&bytes)[5], uintptr_t target) {
    if (bytes[0] != 0xE8) return false;
    int32_t rel = 0;
    std::memcpy(&rel, bytes + 1, 4);
    return at + 5 + static_cast<int64_t>(rel) == target;
}

}  // namespace cdmp::session2::csq
