#include "mod/session2/catch_seq.h"

#include <windows.h>

#include <intrin.h>

#include <safetyhook.hpp>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <format>
#include <initializer_list>
#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "mod/game/build_profile.h"
#include "mod/game/hook_prepare.h"
#include "mod/game/actor_lookup.h"
#include "mod/game/offsets.h"
#include "mod/game/player_reader.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/catch_seq_logic.h"
#include "mod/session2/guest_actor_diag_logic.h"
#include "mod/session2/p8_probe_logic.h"
#include "mod/session2/p8_probes.h"

namespace cdmp::session2 {
namespace {

namespace g2976 = game::build_2976;
using csq::Mode;

// Hooks only at verified function entries inside [0x1000, code_end) (.rsrc, never .xtls).
constexpr uintptr_t kCodeBegin = 0x1000;
// Where the catch is, per build (catch_seq_logic.h). The entry's 25 bytes and every offset are the same in both.
struct Addrs {
    uintptr_t apply, call, ret, check, code_end;
    std::span<const uint8_t> call_bytes, check_bytes;
};
const Addrs kAddrs2976{csq::kApply, csq::kApplyCall, csq::kApplyReturn, csq::kCheckSite, 0x51EB000,
                       csq::kApplyCallBytes, csq::kCheckSiteBytes};
const Addrs kAddrs3527{csq::kApply3527, csq::kApplyCall3527, csq::kApplyReturn3527, csq::kCheckSite3527, 0x5595000,
                       csq::kApplyCallBytes3527, csq::kCheckSiteBytes3527};
const Addrs kAddrs3576{csq::kApply3576, csq::kApplyCall3576, csq::kApplyReturn3576, csq::kCheckSite3576, 0x5597000,
                       csq::kApplyCallBytes3576, csq::kCheckSiteBytes3576};
// Build 1.0.0.3663 (static, 2026-11-13; never run): catch_seq_logic.h; code section end 0x5613000.
const Addrs kAddrs3663{csq::kApply3663, csq::kApplyCall3663, csq::kApplyReturn3663, csq::kCheckSite3663, 0x5613000,
                       csq::kApplyCallBytes3663, csq::kCheckSiteBytes3663};
const Addrs& addrs() noexcept {
    static const Addrs& a = game::current_build() == game::Build::v3663   ? kAddrs3663
                            : game::current_build() == game::Build::v3576 ? kAddrs3576
                            : game::current_build() == game::Build::v3527 ? kAddrs3527
                                                                          : kAddrs2976;
    return a;
}
constexpr uint32_t kTickMs = 500;
constexpr uint32_t kWorldTicks = 6;     // the local player read 6 ticks in a row (3 s) before the hook goes in
constexpr uint64_t kMinuteMs = 60000;
constexpr uint64_t kEventLines = 300;   // per run; after that only counted
constexpr uint64_t kUnread = 0x100;     // an unreadable byte in an event

std::atomic<uint8_t> g_mode{0};  // csq::Mode, written once by catch_seq_start (before the thread)
std::atomic<bool> g_started{false};
std::atomic<bool> g_hook_on{false};
uintptr_t g_base = 0;
SafetyHookInline g_hook;

csq::Tally g_tally;
p8p::EventRing<64> g_ring;

Mode mode() { return static_cast<Mode>(g_mode.load(std::memory_order_acquire)); }

// ---------------------------------------------------------------- guarded access on the game's thread

int access_filter(const EXCEPTION_POINTERS* ep) noexcept {
    const EXCEPTION_RECORD* r = ep ? ep->ExceptionRecord : nullptr;
    if (!r) return EXCEPTION_CONTINUE_SEARCH;
    return r->ExceptionCode == EXCEPTION_ACCESS_VIOLATION || r->ExceptionCode == EXCEPTION_IN_PAGE_ERROR
               ? EXCEPTION_EXECUTE_HANDLER
               : EXCEPTION_CONTINUE_SEARCH;
}
bool plausible(uintptr_t a, size_t n) { return a >= 0x10000 && a <= 0x00007FFFFFFFFFFFull - n; }
// The handler's own locals (arguments 3, 17, 20 point into its frame, already in use): a plain SEH read/write.
bool seh_read8(uintptr_t a, uint8_t& out) noexcept {
    if (!plausible(a, 1)) return false;
    __try {
        out = *reinterpret_cast<const volatile uint8_t*>(a);
        return true;
    } __except (access_filter(GetExceptionInformation())) {
        return false;
    }
}
bool seh_read32(uintptr_t a, uint32_t& out) noexcept {
    if (!plausible(a, 4)) return false;
    __try {
        out = *reinterpret_cast<const volatile uint32_t*>(a);
        return true;
    } __except (access_filter(GetExceptionInformation())) {
        return false;
    }
}
bool seh_write8(uintptr_t a, uint8_t v) noexcept {
    if (!plausible(a, 1)) return false;
    __try {
        *reinterpret_cast<volatile uint8_t*>(a) = v;
        return true;
    } __except (access_filter(GetExceptionInformation())) {
        return false;
    }
}

// The grabber's byte, by the same hops as 0x935E7E..0x935E8E (heap objects: fast_read, SEH, no VirtualQuery).
std::optional<uint8_t> grabber_seq_byte(uintptr_t actor) noexcept {
    const auto comps = game::fast_ptr(actor + csq::kActor_Comps);
    if (!comps) return std::nullopt;
    const auto cc = game::fast_ptr(*comps + csq::kComps_Control);
    if (!cc) return std::nullopt;
    const auto obj = game::fast_ptr(*cc + csq::kControl_Action);
    if (!obj) return std::nullopt;
    return game::fast<uint8_t>(*obj + csq::kAction_Seq);
}

void observe(uintptr_t comp, uintptr_t p_victim, uintptr_t p_c8, uintptr_t p_seq, uintptr_t ret) noexcept {
    csq::Inputs in;
    uint8_t byte = 0;
    in.c8_ok = seh_read8(p_c8, byte);
    in.c8 = byte;
    in.seq_ok = seh_read8(p_seq, byte);
    in.seq = byte;
    uint32_t victim_key = 0;
    const bool victim_key_ok = seh_read32(p_victim, victim_key);
    uint32_t grabber_key = 0;
    uint64_t pending = 0;  // bits 63..32 comp+0x68, 15..8 comp+0x6C, bit 0 / 1: read
    if (const auto actor = game::fast_ptr(comp + csq::kComp_Owner)) {
        if (const auto c = game::fast<uint8_t>(*actor + csq::kActor_Control)) {
            in.grabber_ok = true;
            in.grabber_ctl = *c;
        }
        if (const auto k = game::fast<uint32_t>(*actor + csq::kActor_Key)) grabber_key = *k;
        if (const auto b = grabber_seq_byte(*actor)) {
            in.b_ok = true;
            in.b = *b;
        }
    }
    if (const auto p = game::fast<uint32_t>(comp + csq::kComp_Pending)) pending |= (uint64_t{*p} << 32) | 1;
    if (const auto s = game::fast<uint8_t>(comp + csq::kComp_PendingSeq)) pending |= (uint64_t{*s} << 8) | 2;
    // The victim on this client (the game's own thread owns the actor table; reads with VirtualQuery + SEH).
    if (victim_key_ok && victim_key) {
        if (const auto v = game::find_actor(victim_key)) {
            if (const auto c = game::fast<uint8_t>(*v + csq::kActor_Control)) {
                in.victim_ok = true;
                in.victim_ctl = *c;
            }
        }
    }
    const csq::Decision d = csq::decide(mode(), in);
    bool wrote = false;
    if (d.write) wrote = seh_write8(p_seq, d.value);
    const bool expected_caller = ret == g_base + addrs().ret;
    g_tally.note(in, d, wrote, expected_caller);
    p8p::Event e;
    e.qpc_us = p8_now_us();
    e.tid = GetCurrentThreadId();
    e.kind = 1;
    e.v[0] = grabber_key;
    e.v[1] = victim_key_ok ? victim_key : ~uint64_t{0};
    e.v[2] = in.grabber_ok ? in.grabber_ctl : kUnread;
    e.v[3] = in.victim_ok ? in.victim_ctl : kUnread;
    e.v[4] = in.c8_ok ? in.c8 : kUnread;
    e.v[5] = in.seq_ok ? in.seq : kUnread;
    e.v[6] = in.b_ok ? in.b : kUnread;
    e.v[7] = static_cast<uint64_t>(d.verdict);
    e.v[8] = d.write ? (wrote ? 1u : 2u) : 0u;
    e.v[9] = ret;
    e.v[10] = pending;
    e.v[11] = g_tally.calls.load(std::memory_order_relaxed);
    g_ring.push(e);
}

// ClientCatch_ApplyResult(comp, ...20 arguments, every one 64-bit; rax = its second argument).
using Arg = uint64_t;
Arg apply_detour(Arg comp, Arg a2, Arg a3, Arg a4, Arg a5, Arg a6, Arg a7, Arg a8, Arg a9, Arg a10, Arg a11,
                 Arg a12, Arg a13, Arg a14, Arg a15, Arg a16, Arg a17, Arg a18, Arg a19, Arg a20) {
    observe(comp, a3, a17, a20, reinterpret_cast<uintptr_t>(_ReturnAddress()));
    // Never inside a __try: the game's own exceptions are the game's.
    return g_hook.unsafe_call<Arg>(comp, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17,
                                   a18, a19, a20);
}

// ---------------------------------------------------------------- install (the module's thread, world up)

bool bytes_at(uintptr_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::equal(actual.begin(), actual.end(), expected.begin());
}

bool install_hook() {
    const Addrs& ad = addrs();
    std::vector<gad::Section> secs;
    if (!p8_exe_sections(g_base, secs)) {
        log::error("CatchSeq: the exe's sections are unreadable; the hook on exe+0x{:X} is REFUSED, nothing written",
                   ad.apply);
        return false;
    }
    const auto in_code = [&](uintptr_t rva, size_t n) {
        return rva >= kCodeBegin && rva + n <= ad.code_end &&
               gad::in_real_code(secs, static_cast<uint32_t>(rva), static_cast<uint32_t>(n));
    };
    if (!in_code(ad.apply, sizeof csq::kApplyHead) || !bytes_at(ad.apply, csq::kApplyHead)) {
        log::error("CatchSeq: exe+0x{:X} is not the expected .rsrc entry 48 89 5C 24 08 48 89 74 24 10 48 89 7C 24 18 4C "
                   "89 4C 24 20 55 41 54 41 55; REFUSED, nothing written",
                   ad.apply);
        return false;
    }
    if (!in_code(ad.call, ad.call_bytes.size()) || !bytes_at(ad.call, ad.call_bytes)) {
        log::error("CatchSeq: its only caller exe+0x{:X} is not `call exe+0x{:X}`; REFUSED, nothing written", ad.call,
                   ad.apply);
        return false;
    }
    if (!in_code(ad.check, ad.check_bytes.size()) || !bytes_at(ad.check, ad.check_bytes)) {
        log::error("CatchSeq: the comparison at exe+0x{:X} (argument 17, argument 20, [[[[comp+8]+0x68]+0x40]+0x48]"
                   "+0x93) is not the one this module mirrors; REFUSED, nothing written",
                   ad.check);
        return false;
    }
    const auto* b = std::begin(csq::kApplyBoundaries);
    const auto* e = std::end(csq::kApplyBoundaries);
    auto whole = [&](const std::vector<uint8_t>& o) {
        return std::find(b, e, static_cast<uint32_t>(o.size())) != e && o.size() <= sizeof csq::kApplyHead &&
               std::memcmp(o.data(), csq::kApplyHead, o.size()) == 0;
    };
    // P8 S26 (montura-regresion.md section 7.1): refused attempts logged and tried again (bounded), nothing written.
    auto h = game::prepare_inline(g_base + ad.apply, reinterpret_cast<void*>(&apply_detour), whole, "CatchSeq",
                                  "ClientCatch_ApplyResult");
    if (!h) {
        log::error("CatchSeq: the hook on exe+0x{:X} could not be prepared ({}); REFUSED", ad.apply,
                   game::inline_error_text(h.error()));
        return false;
    }
    const auto& orig = h->original_bytes();
    if (!whole(orig)) {
        log::error("CatchSeq: the hook on exe+0x{:X} would patch {} bytes, not whole verified instructions; REFUSED, "
                   "nothing written",
                   ad.apply, orig.size());
        return false;
    }
    const size_t patched = orig.size();  // `orig` belongs to *h: empty once it is moved
    g_hook = std::move(*h);
    if (!g_hook.enable()) {
        log::error("CatchSeq: the hook on exe+0x{:X} could not be enabled; REFUSED", ad.apply);
        g_hook = {};
        return false;
    }
    g_hook_on.store(true);
    log::info("CatchSeq: exe+0x{:X} (ClientCatch_ApplyResult, the 2156 apply; one caller exe+0x{:X}) hooked at its "
              "entry ({} bytes patched); {}",
              ad.apply, ad.call, patched,
              mode() == Mode::On
                  ? "catch_seq=1: a REMOTE grabber's mismatching sequence is replaced by its byte here when the victim "
                    "is controlled here"
                  : "catch_seq=probe: every grab logged and counted, nothing changed");
    return true;
}

// ---------------------------------------------------------------- the module's thread

bool build_ok() {
    const game::Build b = game::current_build();
    return g_base == g2976::kImageBase &&
           (b == game::Build::v2976 || b == game::Build::v3527 || b == game::Build::v3576 ||
            b == game::Build::v3663);
}

std::string byte_text(uint64_t v) { return v == kUnread ? std::string("unreadable") : std::format("0x{:02X}", v); }
std::string control_text(uint64_t v, const char* missing) {
    if (v == kUnread) return missing;
    return v ? std::format("controlled HERE, +0xC8 = {}", v) : std::string("REMOTE, +0xC8 = 0");
}

void log_event(const p8p::Event& e) {
    const auto verdict = static_cast<csq::Verdict>(e.v[7]);
    std::string action;
    if (verdict == csq::Verdict::RemoteFix) {
        if (e.v[8] == 1) {
            action = std::format(" -> REWRITTEN: argument 20 {} -> {} (the native catch applies)", byte_text(e.v[5]),
                                 byte_text(e.v[6]));
        } else if (e.v[8] == 2) {
            action = " -> the write FAILED (passed through unchanged)";
        } else {
            action = std::format(" -> WOULD REWRITE {} -> {} with catch_seq=1", byte_text(e.v[5]), byte_text(e.v[6]));
        }
    }
    const uint64_t pend = e.v[10];
    const std::string pending =
        std::format("comp+0x68 {} +0x6C {}", (pend & 1) ? std::format("{}", pend >> 32) : std::string("unreadable"),
                    (pend & 2) ? std::format("0x{:02X}", (pend >> 8) & 0xFF) : std::string("unreadable"));
    const uintptr_t ret = static_cast<uintptr_t>(e.v[9]);
    const std::string from =
        ret == g_base + addrs().ret
            ? std::format("from exe+0x{:X} (the 2156 handler)", addrs().ret)
            : (ret >= g_base && ret < g_base + addrs().code_end
                   ? std::format("from exe+0x{:X} (UNEXPECTED caller)", ret - g_base)
                   : std::format("from 0x{:X} (UNEXPECTED caller)", ret));
    log::info("CatchSeq [{}] #{} {}: grabber 0x{:08X} ({}) -> victim {} ({}) | c8 {} | packet seq {} | grabber's byte "
              "[[[[comp+8]+0x68]+0x40]+0x48]+0x93 {} | {}{} | {} | {}",
              csq::mode_name(mode()), e.v[11], p8_when(e.qpc_us), e.v[0], control_text(e.v[2], "unreadable"),
              e.v[1] == ~uint64_t{0} ? std::string("unreadable") : std::format("0x{:08X}", e.v[1]),
              control_text(e.v[3], "not found here"), byte_text(e.v[4]), byte_text(e.v[5]), byte_text(e.v[6]),
              csq::verdict_name(verdict), action, pending, from);
}

void log_summary(uint64_t not_logged) {
    const csq::Tally& t = g_tally;
    const auto n = [](const std::atomic<uint64_t>& c) { return c.load(std::memory_order_relaxed); };
    const bool on = mode() == Mode::On;
    log::info("CatchSeq summary (catch_seq={}): hook {} | calls {} (unexpected caller {}) | grabber here {} | remote "
              "grabber {} | seq match {}, MISMATCH {} | remote mismatches: victim ours {} -> {} {}{}, victim not "
              "controlled here {}, victim not found here {} | no check (c8 0) {} | unreadable {} (arguments {}, grabber "
              "{}, its byte {}) | event lines not logged {}, ring dropped {}",
              csq::mode_name(mode()), g_hook_on.load() ? "on" : "OFF", n(t.calls), n(t.unexpected_caller), n(t.local),
              n(t.remote), n(t.match), n(t.mismatch), n(t.fix), on ? "rewritten" : "would be rewritten with catch_seq=1",
              on ? n(t.rewritten) : n(t.fix), on ? std::format(" (write failed {})", n(t.write_failed)) : std::string(),
              n(t.victim_not_ours), n(t.victim_unknown), n(t.no_check), n(t.unreadable), n(t.unread_args),
              n(t.unread_grabber), n(t.unread_byte), not_logged, g_ring.dropped());
}

DWORD WINAPI worker_thread(LPVOID) {
    try {
        game::PlayerReader reader;
        reader.init();
        uint32_t in_world = 0;
        bool hook_tried = false;
        uint64_t lines = 0, not_logged = 0;
        uint64_t last_minute = GetTickCount64();
        for (;;) {
            Sleep(kTickMs);
            const uint64_t now = GetTickCount64();
            if (!hook_tried) {
                in_world = reader.read() ? in_world + 1 : 0;
                if (in_world < kWorldTicks) continue;
                hook_tried = true;
                if (!install_hook()) {
                    log::error("CatchSeq [{}]: the hook is not in; catch_seq does nothing this run",
                               csq::mode_name(mode()));
                    return 0;
                }
                last_minute = now;
            }
            p8p::Event e;
            while (g_ring.pop(e)) {
                if (lines++ < kEventLines) {
                    log_event(e);
                } else {
                    ++not_logged;
                }
            }
            if (now - last_minute >= kMinuteMs) {
                last_minute = now;
                log_summary(not_logged);
            }
        }
    } catch (...) {
        log::error("CatchSeq: the worker stopped (exception); nothing more is logged (the hook stays as it is)");
    }
    return 0;
}

}  // namespace

void catch_seq_start(const std::string& raw, bool guest) {
    const auto p = csq::parse_mode(raw);
    if (!p.known) {
        log::warn("CatchSeq: catch_seq='{}' is not 0, probe or 1; it stays off", raw);
        return;
    }
    if (p.mode == Mode::Off) return;
    if (guest) {
        log::warn("CatchSeq: catch_seq is for the HOST's PC (the client that controls the enemies); it stays off on "
                  "the guest");
        return;
    }
    if (g_started.exchange(true)) return;
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    if (!build_ok()) {
        log::error("CatchSeq: unsupported game build (not 1.0.0.2976, 3527, 3576 or 3663); catch_seq stays off");
        return;
    }
    g_mode.store(static_cast<uint8_t>(p.mode), std::memory_order_release);
    log::info("CatchSeq ON (catch_seq={}, host): a hook at the entry of ClientCatch_ApplyResult exe+0x{:X} once the world "
              "is up; {}",
              csq::mode_name(p.mode), addrs().apply,
              p.mode == Mode::On
                  ? "every grab logged; a remote grabber's sequence byte is replaced by its value here when the victim "
                    "is controlled here (docs/research/s25/finisher-sigilo.md)"
                  : "every grab logged and counted, nothing changed (docs/research/s25/finisher-sigilo.md)");
    if (HANDLE h = CreateThread(nullptr, 0, worker_thread, nullptr, 0, nullptr)) CloseHandle(h);
}

}  // namespace cdmp::session2
