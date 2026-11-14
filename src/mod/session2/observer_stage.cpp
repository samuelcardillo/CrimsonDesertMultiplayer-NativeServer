#include "mod/session2/observer_stage.h"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <format>
#include <map>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "mod/game/build_profile.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/guest_actor_diag_logic.h"
#include "mod/session2/guest_stage_diag_logic.h"
#include "mod/session2/host_scene_diag.h"
#include "mod/session2/observer_milestone.h"
#include "mod/session2/observer_scene_copy.h"
#include "mod/session2/observer_stage_logic.h"
#include "mod/session2/offsets_s2.h"
#include "mod/session2/p8_probe_logic.h"
#include "mod/session2/p8_probes.h"

namespace cdmp::session2 {
namespace {

namespace p = p8p;

// ---------------------------------------------------------------- the points (build 2976, .rsrc)
//
// Read from the authorised read-only PE (D:\RE\CrimsonDesert_2976\bin\CrimsonDesert.exe,
// SHA-256 57DA440D...E1E7) with capstone: every patch is whole instructions from
// the function start (.pdata), no branch of the function and no rel32
// (E8/E9/0F8x) of .rsrc/.xtls/.text lands strictly inside it, no RIP-relative
// operand in it (docs/research/pendientes/p8-observador-escenas.md §7).

// PrepareSequencerAck 2661's serializer (only caller 0x287D03C in 0x287C200):
//   0x2A4DEF0 mov [rsp+8],rbx ; mov [rsp+0x20],r9 ; mov [rsp+0x18],r8 ; push rbp   patch 5
// 0x2A4E024/0x2A4E030: n = u32 [r9+8], entries [r9] stride 0xC (u32 node, u32 actor, 3 x u8);
// 0x2A4E01F call 0x244BA90(stream, r8): u32 [r8+0] (owner actor), u64 [r8+8] (sequencer id), ...
constexpr uintptr_t kPrepare = 0x2A4DEF0;
constexpr uint8_t kPrepareBytes[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x4C, 0x89, 0x4C,
                                     0x24, 0x20, 0x4C, 0x89, 0x44, 0x24, 0x18, 0x55};
constexpr uintptr_t kPrepareLoop = 0x2A4E024;  // mov eax,[r13+8] ; test eax,eax ; je ; mov r14d,eax ; nop ; mov rdi,[r13+0]
constexpr uint8_t kPrepareLoopBytes[] = {0x41, 0x8B, 0x45, 0x08, 0x85, 0xC0, 0x74, 0x73, 0x44,
                                         0x8B, 0xF0, 0x90, 0x49, 0x8B, 0x7D, 0x00};
constexpr uintptr_t kPrepareOpcode = 0x2A4E09F;  // mov word [r15],0xA65
constexpr uint8_t kPrepareOpcodeBytes[] = {0x66, 0x41, 0xC7, 0x07, 0x65, 0x0A};

// DeleteSequencerAck 2810's serializer (only caller 0x2879819 in 0x2879440):
//   0x2A4E4C0 mov [rsp+8],rbx ; mov [rsp+0x20],r9 ; push rbp ...                  patch 5
// 0x2A4E4E1 mov r12,r8 ... 0x2A4E5C2 mov rax,[r12] (the u64 sequencer id).
constexpr uintptr_t kDelete = 0x2A4E4C0;
constexpr uint8_t kDeleteBytes[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x4C, 0x89, 0x4C,
                                    0x24, 0x20, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41};
constexpr uintptr_t kDeleteSeq = 0x2A4E5C2;  // mov rax,[r12]
constexpr uint8_t kDeleteSeqBytes[] = {0x49, 0x8B, 0x04, 0x24};
constexpr uintptr_t kDeleteOpcode = 0x2A4E60C;  // mov word [r14],0xAFA
constexpr uint8_t kDeleteOpcodeBytes[] = {0x66, 0x41, 0xC7, 0x06, 0xFA, 0x0A};

// StageBranchStateAck 2981's serializer (only caller .xtls 0x103FB3FD: observed, never called):
//   0x2A4F2D0 mov [rsp+8],rbx ; mov [rsp+0x20],r9 ; mov [rsp+0x18],r8 ; push rbp   patch 5
// 0x2A4F3F8 mov rcx,[rbp+0x67] (r8's home) ; mov rax,[rcx] -> the u64 sequencer id; r9 -> the u32
// written next (0x2A4F2F6 mov r13,r9 ... 0x2A4F41F mov rdx,r13 ; r8d = 4).
constexpr uintptr_t kBranch = 0x2A4F2D0;
constexpr uint8_t kBranchBytes[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x4C, 0x89, 0x4C,
                                    0x24, 0x20, 0x4C, 0x89, 0x44, 0x24, 0x18, 0x55};
constexpr uintptr_t kBranchSeq = 0x2A4F3F8;
constexpr uint8_t kBranchSeqBytes[] = {0x48, 0x8B, 0x4D, 0x67, 0x48, 0x8B, 0x01};
constexpr uintptr_t kBranchOpcode = 0x2A4F486;  // mov word [r15],0xBA5
constexpr uint8_t kBranchOpcodeBytes[] = {0x66, 0x41, 0xC7, 0x07, 0xA5, 0x0B};

// PlayAllPreLoadSequencerAck 2322's emitter (only direct caller 0x287F1D4 in 0x287EF60):
//   0x2999D80 mov [rsp+8],rbx ; push rbp ; push rsi ...                           patch 5
constexpr uintptr_t kMilestone = 0x2999D80;
constexpr uint8_t kMilestoneBytes[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x55, 0x56, 0x57,
                                       0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57};
constexpr uintptr_t kMilestoneOpcode = 0x2999E77;  // mov word [r14],0x912
constexpr uint8_t kMilestoneOpcodeBytes[] = {0x66, 0x41, 0xC7, 0x06, 0x12, 0x09};

// MoveFieldCompleteCore 0x2BC7670 (r13 = field from r8 at 0x2BC769E, r14 = the travelling
// actor from [rcx+8] at 0x2BC76AA; on the success path neither is written again before):
//   0x2BC84D9 mov rcx,[rsi+0x18] ; call 0x2841D00   (the non-owner jne lands here; the owner
//             path falls through after 0x2BC84D4 call 0x287EF60)
//   0x2BC84E2 mov rax,[r13+0x2D0]                                                patch 7
// Outside every range the P8 probes patch or check (0x2BC8452..0x2BC8479, 0x2BC84D4..0x2BC84D8).
constexpr uintptr_t kEntry = 0x2BC84E2;
constexpr uint32_t kEntryPatch = 7;
constexpr uint8_t kEntryBytes[] = {0x49, 0x8B, 0x85, 0xD0, 0x02, 0x00, 0x00, 0x48,
                                   0x85, 0xC0, 0x75, 0x07, 0xB8, 0xFF, 0xFF, 0x00};
constexpr uintptr_t kEntryPred = 0x2BC84D9;
constexpr uint8_t kEntryPredBytes[] = {0x48, 0x8B, 0x4E, 0x18, 0xE8, 0x1E, 0x98, 0xC7, 0xFF};
constexpr uintptr_t kEntryR13 = 0x2BC769E;  // mov r13,r8
constexpr uint8_t kEntryR13Bytes[] = {0x4D, 0x8B, 0xE8};
constexpr uintptr_t kEntryR14 = 0x2BC76AA;  // mov r14,[rcx+8]
constexpr uint8_t kEntryR14Bytes[] = {0x4C, 0x8B, 0x71, 0x08};

constexpr uint32_t kPatch5 = 5;

// pa::ToTargetSendTargetFinder's vtable (0x287D003 / 0x2BC78E3 lea) and its base ISendTargetFinder.
constexpr uintptr_t kVtToTarget = 0x5B25438;
constexpr uintptr_t kVtFinderBase = 0x5B253F8;

constexpr uint32_t kActor_Key = 0x60, kActor_User = 0xA0, kUser_Key = 0x60;
constexpr uint32_t kField_Owner = 0x180, kField_Key = 0x2C8;
constexpr uint32_t kFinder_Session = 0x10;
constexpr uint32_t kBindingStride = 0x0C;

// ---------------------------------------------------------------- events

enum Kind : uint16_t { kKPrepare = 0, kKPrepareMore, kKDelete, kKBranch, kKMilestone, kKEntry, kKindCount };
constexpr const char* kKindName[kKindCount] = {"2661 PrepareSequencerAck", "2661 bindings", "2810 DeleteSequencerAck",
                                               "2981 StageBranchStateAck", "2322 PlayAllPreLoadSequencerAck",
                                               "entry 0x2BC84E2"};
constexpr uint16_t kFlagPlayData = 1, kFlagVector = 2, kFlagSeq = 4, kFlagExtra = 8;
constexpr size_t kInlineBindings = 6;  // in the 2661 event itself
constexpr size_t kMoreBindings = 9;    // per continuation event

constexpr uint64_t kWindowUs = 5'000'000;
constexpr uint32_t kPerWindow = 512;
constexpr uint64_t kMaxLinesPerKind = 4000;

struct KindStats {
    std::atomic<uint64_t> hits{0}, queued{0}, limited{0}, dropped{0};
};

uintptr_t g_base = 0;
std::vector<gad::Section> g_secs;
std::atomic<bool> g_started{false}, g_on{false}, g_send_refused{false};
p::EventRing<4096> g_ring;
KindStats g_stats[kKindCount];
p::WindowLimiter g_lim[kKindCount] = {{kPerWindow, kWindowUs}, {kPerWindow, kWindowUs}, {kPerWindow, kWindowUs},
                                      {kPerWindow, kWindowUs}, {kPerWindow, kWindowUs}, {kPerWindow, kWindowUs}};
std::atomic<uint64_t> g_lines[kKindCount] = {};
std::atomic<uint32_t> g_hooked{0}, g_wanted{0};
std::atomic<uint64_t> g_entries{0}, g_observer_entries{0};
std::atomic<size_t> g_live{0};
SafetyHookMid g_hooks[kKindCount];
std::atomic<uint64_t> g_install_us{0};

// ---------------------------------------------------------------- hot path (no CRT, no allocation)

template <class T>
bool rd(uintptr_t a, T& v) noexcept {
    if (a < 0x10000) return false;
    __try {
        v = *reinterpret_cast<const volatile T*>(a);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

template <class T>
T rdv(uintptr_t a, T fallback = T{}) noexcept {
    T v{};
    return rd(a, v) ? v : fallback;
}

uint32_t actor_key(uintptr_t actor) noexcept { return actor ? rdv<uint32_t>(actor + kActor_Key) : 0; }

uint32_t actor_user_key(uintptr_t actor) noexcept {
    const uintptr_t user = actor ? rdv<uintptr_t>(actor + kActor_User) : 0;
    return user ? rdv<uint32_t>(user + kUser_Key) : 0;
}

void emit(Kind k, p::Event& e) noexcept {
    e.kind = k;
    if (!e.qpc_us) e.qpc_us = p8_now_us();
    e.tid = GetCurrentThreadId();
    if (!g_lim[k].take(e.qpc_us)) {
        g_stats[k].limited.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (g_ring.push(e)) {
        g_stats[k].queued.fetch_add(1, std::memory_order_relaxed);
    } else {
        g_stats[k].dropped.fetch_add(1, std::memory_order_relaxed);
    }
}

// The four packets: who it is addressed to and through which finder.
void common(p::Event& e, uintptr_t actor, uintptr_t finder) noexcept {
    e.v[0] = actor_key(actor) | static_cast<uint64_t>(actor_user_key(actor)) << 32;
    e.v[1] = finder ? rdv<uintptr_t>(finder) : 0;
    e.v[2] = actor;
    e.v[3] = finder ? rdv<uintptr_t>(finder + kFinder_Session) : 0;
}

void on_prepare(safetyhook::Context& ctx) noexcept {
    g_stats[kKPrepare].hits.fetch_add(1, std::memory_order_relaxed);
    p::Event e;
    e.qpc_us = p8_now_us();
    common(e, ctx.rcx, ctx.rdx);
    const uintptr_t play = ctx.r8, vec = ctx.r9;
    uint32_t owner = 0, n = 0;
    uint64_t seq = 0;
    uintptr_t base = 0;
    if (rd(play, owner) && rd(play + 8, seq)) e.flags |= kFlagPlayData;
    if (rd(vec, base) && rd(vec + 8, n)) e.flags |= kFlagVector;
    if (!(e.flags & kFlagVector)) n = 0;
    e.v[4] = owner | static_cast<uint64_t>(n) << 32;
    e.v[5] = seq;
    const size_t keep = n < obs::kMaxBindings ? n : obs::kMaxBindings;
    size_t i = 0;
    for (; i < keep && i < kInlineBindings; ++i) {
        const uintptr_t b = base + i * kBindingStride;
        e.v[6 + i] = rdv<uint32_t>(b) | static_cast<uint64_t>(rdv<uint32_t>(b + 4)) << 32;
    }
    const uint32_t actor = static_cast<uint32_t>(e.v[0]);
    const uint64_t t = e.qpc_us;
    emit(kKPrepare, e);
    while (i < keep) {  // the rest, in order, from this same thread
        p::Event m;
        m.qpc_us = t;
        m.v[0] = actor;
        m.v[1] = seq;
        const size_t start = i;
        size_t j = 0;
        for (; i < keep && j < kMoreBindings; ++i, ++j) {
            const uintptr_t b = base + i * kBindingStride;
            m.v[3 + j] = rdv<uint32_t>(b) | static_cast<uint64_t>(rdv<uint32_t>(b + 4)) << 32;
        }
        m.v[2] = start | static_cast<uint64_t>(j) << 32;
        emit(kKPrepareMore, m);
    }
}

void on_delete(safetyhook::Context& ctx) noexcept {
    // P8 review M6: the nested call of our own copy (observer_scene_copy) is not a native 2810: not in the
    // ledger (and the copy itself lets it through untouched).
    if (observer_scene_copy_in_copy()) return;
    g_stats[kKDelete].hits.fetch_add(1, std::memory_order_relaxed);
    p::Event e;
    common(e, ctx.rcx, ctx.rdx);
    uint64_t seq = 0;
    uint32_t extra = 0;
    if (rd(ctx.r8, seq)) e.flags |= kFlagSeq;
    if (rd(ctx.r9, extra)) e.flags |= kFlagExtra;
    e.v[4] = seq;
    e.v[5] = extra;
    emit(kKDelete, e);
    // P8 (observer_scene_copy.h): a scene of user 2's closed toward another character gets the native
    // 2810 once more for user 2, on this thread (returns at once when off; its own call is seen here too).
    observer_scene_copy_on_delete(ctx.rcx, ctx.r8, ctx.r9, ctx.rsi, ctx.r12, ctx.rsp);
}

void on_branch(safetyhook::Context& ctx) noexcept {
    g_stats[kKBranch].hits.fetch_add(1, std::memory_order_relaxed);
    p::Event e;
    common(e, ctx.rcx, ctx.rdx);
    uint64_t seq = 0;
    uint32_t value = 0;
    if (rd(ctx.r8, seq)) e.flags |= kFlagSeq;
    if (rd(ctx.r9, value)) e.flags |= kFlagExtra;  // 0x2A4F2F6 mov r13,r9 ; 0x2A4F41F mov rdx,r13: written 4 bytes
    e.v[4] = seq;
    e.v[5] = value;
    emit(kKBranch, e);
}

void on_milestone(safetyhook::Context& ctx) noexcept {
    g_stats[kKMilestone].hits.fetch_add(1, std::memory_order_relaxed);
    p::Event e;
    common(e, ctx.rcx, ctx.rdx);
    emit(kKMilestone, e);
}

void on_entry(safetyhook::Context& ctx) noexcept {
    g_stats[kKEntry].hits.fetch_add(1, std::memory_order_relaxed);
    const uintptr_t field = ctx.r13, actor = ctx.r14;
    p::Event e;
    e.v[0] = actor_key(actor) | static_cast<uint64_t>(actor_user_key(actor)) << 32;
    e.v[1] = rdv<uint32_t>(field + kField_Owner) | static_cast<uint64_t>(rdv<uint32_t>(field + kField_Key)) << 32;
    e.v[2] = field;
    e.v[3] = actor;
    emit(kKEntry, e);
    // P8 S2 (observer_milestone.h): the decision, and with observer_milestone_send=1 the native
    // 2322, on this thread inside MoveFieldCompleteCore (returns at once when off).
    observer_milestone_on_entry(field, actor);
    // P8 S1 (host_scene_diag.h, s1_scene_diag): a fixed record of the entry (returns at once when off).
    host_scene_diag_on_entry(field, actor);
}

// ---------------------------------------------------------------- drain thread: ledger and lines

std::string rva_text(uintptr_t a) {
    return a >= g_base && a - g_base < 0x10000000 ? std::format("exe+0x{:X}", a - g_base) : std::format("0x{:X}", a);
}

std::string finder_text(uintptr_t vt) {
    if (vt == g_base + kVtToTarget) return "ToTarget";
    if (vt == g_base + kVtFinderBase) return "ISendTargetFinder (base)";
    return vt ? std::format("finder vt {}", rva_text(vt)) : std::string("no finder");
}

bool targeted(uintptr_t vt) { return vt == g_base + kVtToTarget; }

std::string seq_text(uint64_t s) { return std::format("0x{:X}", s); }

std::string bindings_text(const std::vector<obs::Binding>& bs, uint32_t total) {
    std::string s;
    for (const obs::Binding& b : bs) s += std::format(" 0x{:08X}->0x{:08X}", b.node, b.actor);
    if (total > bs.size()) s += std::format(" (+{} not kept)", total - bs.size());
    return s.empty() ? std::string(" none") : s;
}

struct Pending {
    obs::SeqEntry entry;
    uintptr_t finder_vt = 0, session = 0;
    uint64_t qpc = 0;
    uint32_t tid = 0;
    size_t expected = 0;
    bool play_ok = false, vec_ok = false;
};

obs::Ledger g_ledger(1024);
std::map<std::pair<uint32_t, uint64_t>, Pending> g_pending;  // drain thread only
std::vector<obs::EntryWatch> g_watches;                       // drain thread only (the last 8)

void write_line(Kind k, const std::string& s) {
    if (g_lines[k].fetch_add(1) + 1 > kMaxLinesPerKind) return;
    try {
        log::info("{}", s);
    } catch (...) {
    }
}

std::string head(Kind k, uint64_t qpc, uint32_t tid) {
    return std::format("ObserverStage [{}] {} T{} |", kKindName[k], p8_when(qpc), tid);
}

void count_watches(uint16_t opcode, uint32_t user, bool is_targeted) {
    for (obs::EntryWatch& w : g_watches) w.count(opcode, user, is_targeted);
}

void finish_prepare(Pending& pd) {
    obs::SeqEntry& e = pd.entry;
    const uint32_t user = e.user;
    const std::string line = std::format(
        "{} 2661 size {} (5 + 91 + 11 x {}) -> actor 0x{:08X} user 0x{:08X} via {} (session 0x{:X}) | owner actor "
        "0x{:08X} sequencer {}{} | {} | bindings {}:{}",
        head(kKPrepare, pd.qpc, pd.tid), obs::prepare_wire_size(e.bindings_total), e.bindings_total, e.actor, user,
        finder_text(pd.finder_vt), pd.session, e.owner_actor, seq_text(e.seq),
        pd.play_ok ? "" : " (play data UNREADABLE)", gsd::corr_token(obs::kOpPrepare, e.actor, e.seq, e.bindings_total),
        e.bindings_total,
        pd.vec_ok ? bindings_text(e.bindings, e.bindings_total) : std::string(" UNREADABLE"));
    const bool is_targeted = targeted(pd.finder_vt);
    e.targeted = is_targeted;
    g_ledger.prepare(std::move(e));
    g_live.store(g_ledger.live());
    write_line(kKPrepare, line + std::format(" | live sequencers {}", g_ledger.live()));
    count_watches(obs::kOpPrepare, user, is_targeted);
}

void flush_pending() {
    for (auto& [k, pd] : g_pending) finish_prepare(pd);
    g_pending.clear();
}

void on_entry_event(const p::Event& ev) {
    const uint32_t actor = static_cast<uint32_t>(ev.v[0]), user = static_cast<uint32_t>(ev.v[0] >> 32);
    const uint32_t owner = static_cast<uint32_t>(ev.v[1]), field_key = static_cast<uint32_t>(ev.v[1] >> 32);
    g_entries.fetch_add(1);
    const std::string h = head(kKEntry, ev.qpc_us, ev.tid);
    if (user == owner) {
        // Its earlier sequencers belonged to the field it left (its client resets the manager on the change).
        const size_t dropped = g_ledger.drop_user_before(user, ev.qpc_us);
        g_live.store(g_ledger.live());
        write_line(kKEntry, std::format("{} user 0x{:08X} actor 0x{:08X} completed its entry into field 0x{:X} (key "
                                        "0x{:08X}) it OWNS: the native stage sync (0x2910DE0) and preparation "
                                        "(0x287EF60, its 2322) run for it | ledger: {} sequencer(s) of its previous "
                                        "field dropped | live sequencers {}",
                                        h, user, actor, ev.v[2], field_key, dropped, g_ledger.live()));
        return;
    }
    g_observer_entries.fetch_add(1);
    const obs::ObserverNeed n = g_ledger.need(owner, user);
    std::string seqs;
    for (const obs::SeqEntry* e : n.missing) {
        seqs += std::format(" {}({} binding{}{})", seq_text(e->seq), e->bindings_total,
                            e->bindings_total == 1 ? "" : "s",
                            e->has_branch ? std::format(", branch {}", e->branch_value) : std::string());
    }
    std::string actors;
    for (uint32_t a : n.bound_actors) actors += std::format(" 0x{:08X}", a);
    std::string order;
    for (const obs::PlanStep& s : obs::native_order(n)) {
        order += s.opcode == obs::kOpMilestone ? std::string(" 2322") : std::format(" {}({})", s.opcode, seq_text(s.seq));
    }
    write_line(kKEntry,
               std::format("{} user 0x{:08X} actor 0x{:08X} completed its entry into field 0x{:X} (key 0x{:08X}) "
                           "owned by user 0x{:08X} -> NOT the owner (observer): natively 0x2BC788C skipped the stage "
                           "sync 0x2910DE0 and 0x2BC8473 skipped 0x287EF60 and its 2322 | the owner's live sequencers "
                           "(prepared ToTarget the owner since {}): {}, also prepared for this user: {} | MISSING for "
                           "the observer: {} sequencer(s):{} | NPCs they bind ({}{}):{} | PLAN, NOT SENT "
                           "(observer_stage_sync=1 measures only): {} x 2661 (+ its 2981 state), then 2322 for actor "
                           "0x{:08X}; native order:{} | NOT SENT BECAUSE (p8-observador-escenas.md Fase 2): user 2's "
                           "client routes every 2661/2981 to the manager of ITS field owner (its own character, "
                           "0x9A5BE0 via the one current ClientField), while these NPCs search the manager of the "
                           "sequencer owner 0x{:08X} (0x9ED290); see the guest's 'GuestStage' lines",
                           h, user, actor, ev.v[2], field_key, owner, p8_when(g_install_us.load()), n.owner_live,
                           n.delivered, n.missing.size(), seqs.empty() ? std::string(" none") : seqs,
                           n.bound_actors.size(),
                           n.bindings_unknown ? std::format(", {} more not kept", n.bindings_unknown) : std::string(),
                           actors.empty() ? std::string(" none") : actors, n.missing.size(), actor, order,
                           n.missing.empty() ? 0u : n.missing.front()->owner_actor) +
                   (observer_milestone_mode() == oms::Mode::Off
                        ? std::string()
                        : std::format(" | THE 2322 ALONE (no snapshot) is decided by observer_milestone ({}): see the "
                                      "'ObserverMilestone [decision]' line of this entry",
                                      oms::mode_name(observer_milestone_mode()))));
    obs::EntryWatch w;
    w.observer_user = user;
    w.observer_actor = actor;
    w.owner_user = owner;
    w.t_us = ev.qpc_us;
    if (g_watches.size() >= 8) g_watches.erase(g_watches.begin());
    g_watches.push_back(w);
}

void follow_ups() {
    const uint64_t now = p8_now_us();
    for (obs::EntryWatch& w : g_watches) {
        for (int i = obs::follow_up_due(w, now); i >= 0; i = obs::follow_up_due(w, now)) {
            w.reported |= static_cast<uint8_t>(1u << i);
            const obs::ObserverNeed n = g_ledger.need(w.owner_user, w.observer_user);
            write_line(kKEntry,
                       std::format("ObserverStage [since entry +{} s] user 0x{:08X} actor 0x{:08X} in user 0x{:08X}'s "
                                   "field (entry {}): addressed to it since: 2661 x{}, 2810 x{}, 2981 x{}, 2322 x{} | "
                                   "2981 of the owner's sequencers through a non-ToTarget finder x{} | the owner's live "
                                   "sequencers now {}, still missing for it {}{}",
                                   obs::kFollowUpUs[i] / 1'000'000, w.observer_user, w.observer_actor, w.owner_user,
                                   p8_when(w.t_us), w.prepares, w.deletes, w.branches, w.milestones,
                                   w.owner_branches_untargeted, n.owner_live, n.missing.size(),
                                   w.milestones ? std::string()
                                                : std::string(" | NO 2322 reached it: its loading state 0x11 waits on "
                                                              "M+0x231 (guest: P8Probe [loading 0x779E48])")));
        }
    }
}

void drain() {
    p::Event e;
    while (g_ring.pop(e)) {
        if (e.kind >= kKindCount) continue;
        switch (e.kind) {
            case kKPrepare: {
                Pending pd;
                pd.qpc = e.qpc_us;
                pd.tid = e.tid;
                pd.finder_vt = e.v[1];
                pd.session = e.v[3];
                pd.play_ok = e.flags & kFlagPlayData;
                pd.vec_ok = e.flags & kFlagVector;
                pd.entry.actor = static_cast<uint32_t>(e.v[0]);
                pd.entry.user = static_cast<uint32_t>(e.v[0] >> 32);
                pd.entry.owner_actor = static_cast<uint32_t>(e.v[4]);
                pd.entry.bindings_total = static_cast<uint32_t>(e.v[4] >> 32);
                pd.entry.seq = e.v[5];
                pd.entry.t_us = e.qpc_us;
                pd.expected = std::min<size_t>(pd.entry.bindings_total, obs::kMaxBindings);
                for (size_t i = 0; i < kInlineBindings && pd.entry.bindings.size() < pd.expected; ++i) {
                    pd.entry.bindings.push_back(
                        {static_cast<uint32_t>(e.v[6 + i]), static_cast<uint32_t>(e.v[6 + i] >> 32)});
                }
                const auto key = std::make_pair(pd.entry.actor, pd.entry.seq);
                if (auto it = g_pending.find(key); it != g_pending.end()) {  // an older one never completed
                    finish_prepare(it->second);
                    g_pending.erase(it);
                }
                if (pd.entry.bindings.size() >= pd.expected) {
                    finish_prepare(pd);
                } else {
                    g_pending.emplace(key, std::move(pd));
                }
                break;
            }
            case kKPrepareMore: {
                const auto key = std::make_pair(static_cast<uint32_t>(e.v[0]), e.v[1]);
                auto it = g_pending.find(key);
                if (it == g_pending.end()) break;  // its 2661 event was limited or dropped
                const size_t count = static_cast<uint32_t>(e.v[2] >> 32);
                for (size_t j = 0; j < count && j < kMoreBindings; ++j) {
                    it->second.entry.bindings.push_back(
                        {static_cast<uint32_t>(e.v[3 + j]), static_cast<uint32_t>(e.v[3 + j] >> 32)});
                }
                if (it->second.entry.bindings.size() >= it->second.expected) {
                    finish_prepare(it->second);
                    g_pending.erase(it);
                }
                break;
            }
            case kKDelete: {
                flush_pending();
                const uint32_t actor = static_cast<uint32_t>(e.v[0]), user = static_cast<uint32_t>(e.v[0] >> 32);
                const bool was = (e.flags & kFlagSeq) && g_ledger.remove(actor, e.v[4]);
                g_live.store(g_ledger.live());
                write_line(kKDelete,
                           std::format("{} 2810 size 22 -> actor 0x{:08X} user 0x{:08X} via {} | sequencer {}{} u32 "
                                       "{} | {} | {} | live sequencers {}",
                                       head(kKDelete, e.qpc_us, e.tid), actor, user, finder_text(e.v[1]),
                                       seq_text(e.v[4]), (e.flags & kFlagSeq) ? "" : " (UNREADABLE)", e.v[5],
                                       gsd::corr_token(obs::kOpDelete, actor, e.v[4], static_cast<uint32_t>(e.v[5])),
                                       was ? "removed from the ledger" : "NOT in the ledger", g_ledger.live()));
                count_watches(obs::kOpDelete, user, targeted(e.v[1]));
                break;
            }
            case kKBranch: {
                flush_pending();
                const uint32_t actor = static_cast<uint32_t>(e.v[0]), user = static_cast<uint32_t>(e.v[0] >> 32);
                const uint32_t value = static_cast<uint32_t>(e.v[5]);
                const bool live = (e.flags & kFlagSeq) && g_ledger.branch(actor, e.v[4], value, e.qpc_us);
                write_line(kKBranch, std::format("{} 2981 (size: see the capture) -> actor 0x{:08X} user 0x{:08X} "
                                                 "via {} | sequencer {}{} u32 {}{} | {} | {}",
                                                 head(kKBranch, e.qpc_us, e.tid), actor, user, finder_text(e.v[1]),
                                                 seq_text(e.v[4]), (e.flags & kFlagSeq) ? "" : " (UNREADABLE)", value,
                                                 (e.flags & kFlagExtra) ? "" : " (UNREADABLE)",
                                                 gsd::corr_token(obs::kOpBranch, actor, e.v[4], value),
                                                 live ? "a live sequencer" : "not a live sequencer of the ledger"));
                count_watches(obs::kOpBranch, user, targeted(e.v[1]));
                break;
            }
            case kKMilestone: {
                flush_pending();
                const uint32_t actor = static_cast<uint32_t>(e.v[0]), user = static_cast<uint32_t>(e.v[0] >> 32);
                write_line(kKMilestone, std::format("{} 2322 size 9 -> actor 0x{:08X} user 0x{:08X} via {} (session "
                                                    "0x{:X}) | {} | live sequencers prepared for this user {}",
                                                    head(kKMilestone, e.qpc_us, e.tid), actor, user,
                                                    finder_text(e.v[1]), e.v[3],
                                                    gsd::corr_token(obs::kOpMilestone, actor, 0, 0),
                                                    g_ledger.need(user, 0).owner_live));
                count_watches(obs::kOpMilestone, user, targeted(e.v[1]));
                break;
            }
            case kKEntry:
                flush_pending();
                on_entry_event(e);
                break;
            default:
                break;
        }
    }
    flush_pending();
    follow_ups();
}

std::string counters() {
    std::string s = std::format("ObserverStage (measure only{}) | hooked {}/{} | ring dropped {} | ledger: live {} "
                                "prepared {} replaced {} deleted {} (unknown {}) 2981 {} (not live {}) full {} "
                                "dropped at the owner's field changes {} | entries {} (observer {})",
                                g_send_refused.load() ? ", send mode REFUSED" : "", g_hooked.load(), g_wanted.load(),
                                g_ring.dropped(), g_live.load(), g_ledger.prepared(), g_ledger.replaced(),
                                g_ledger.deleted(), g_ledger.delete_unknown(), g_ledger.branches(),
                                g_ledger.branch_unknown(), g_ledger.full(), g_ledger.invalidated(), g_entries.load(),
                                g_observer_entries.load());
    for (int k = 0; k < kKindCount; ++k) {
        const KindStats& st = g_stats[k];
        s += std::format(" | {}: hits {} queued {} limited {} dropped {} lines {}", kKindName[k], st.hits.load(),
                         st.queued.load(), st.limited.load(), st.dropped.load(), g_lines[k].load());
    }
    return s;
}

// ---------------------------------------------------------------- install

template <class T>
bool peek(uintptr_t a, T& v) {
    return a && game::safe_read(a, &v, sizeof v);
}

bool read_sections() {
    g_secs.clear();
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (!peek(g_base, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || !peek(g_base + dos.e_lfanew, nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    const uintptr_t first = g_base + dos.e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                            nt.FileHeader.SizeOfOptionalHeader;
    for (WORD i = 0; i < nt.FileHeader.NumberOfSections && i < 64; ++i) {
        IMAGE_SECTION_HEADER h{};
        if (!peek(first + i * sizeof h, h)) return false;
        gad::Section s;
        std::copy(std::begin(h.Name), std::end(h.Name), s.name);
        s.va = h.VirtualAddress;
        s.size = h.Misc.VirtualSize;
        s.flags = h.Characteristics;
        g_secs.push_back(s);
    }
    return !g_secs.empty();
}

bool bytes_at(uintptr_t rva, std::span<const uint8_t> expected) {
    std::vector<uint8_t> actual(expected.size());
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::equal(actual.begin(), actual.end(), expected.begin());
}

struct Ctx {
    uintptr_t rva;
    std::span<const uint8_t> bytes;
};

// Build 1.0.0.3527: only the 2810 hook, for observer_scene_copy. The serializer is 0x2CDAB60, DeleteSequencer's call of
// it is 0x2AD4640 and there the sequencer is in rdi and the manager in r13.
constexpr uintptr_t kDelete3527 = 0x2CDAB60;
constexpr uint8_t kDeleteBytes3527[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x4C, 0x89, 0x4C,
                                        0x24, 0x20, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41};

// Build 1.0.0.3576 (static, 2026-11-06; not yet run): the serializer moved whole by +0xC70 with the same bytes
// (0x2CDAB60 -> 0x2CDB7D0, .pdata begins there; it still writes the native opcode 0x8F4). The caller registers the
// callback reads are observer_scene_copy's to verify (observer_scene_copy_verify_current), as on 3527.
constexpr uintptr_t kDelete3576 = 0x2CDB7D0;
constexpr uintptr_t kWorldSlot3576 = 0x71C0100;  // reader_profile() may be null on 3576
// Build 1.0.0.3663 (static, 2026-11-13; never run): the serializer is 0x2D42250 (3527's 0x2CDAB60 + 0x676F0; .pdata to
// 0x2D42725), kDeleteBytes3527 at its entry; it is the only function that writes DeleteSequencerAck's 3663 native
// (`mov word [r14],0xA63` at 0x2D4239C; 2292 -> 2659, opcode_mapping_3576_3663.json), and DeleteSequencer 0x2B393C0
// calls it at 0x2B39783 (the exe's only rel32 call to it; observer_scene_copy.cpp kLayout3663 has the same 0x2D42250).
// World slot 0x72451C0 (core_globals_3663.json).
constexpr uintptr_t kDelete3663 = 0x2D42250;
constexpr uintptr_t kWorldSlot3663 = 0x72451C0;

void on_delete_3527(safetyhook::Context& ctx) noexcept {
    observer_scene_copy_on_delete(ctx.rcx, ctx.r8, ctx.r9, ctx.rdi, ctx.r13, ctx.rsp);
}

struct PointDef {
    Kind kind;
    uintptr_t rva;
    uint32_t patch;
    std::span<const uint8_t> bytes;
    std::vector<Ctx> ctx;  // code the callback's register reading relies on (checked, never patched)
    safetyhook::MidHookFn fn;
};

std::vector<PointDef> points() {
    return {
        {kKPrepare, kPrepare, kPatch5, kPrepareBytes,
         {{kPrepareLoop, kPrepareLoopBytes}, {kPrepareOpcode, kPrepareOpcodeBytes}}, on_prepare},
        {kKDelete, kDelete, kPatch5, kDeleteBytes, {{kDeleteSeq, kDeleteSeqBytes}, {kDeleteOpcode, kDeleteOpcodeBytes}},
         on_delete},
        {kKBranch, kBranch, kPatch5, kBranchBytes, {{kBranchSeq, kBranchSeqBytes}, {kBranchOpcode, kBranchOpcodeBytes}},
         on_branch},
        {kKMilestone, kMilestone, kPatch5, kMilestoneBytes, {{kMilestoneOpcode, kMilestoneOpcodeBytes}}, on_milestone},
        {kKEntry, kEntry, kEntryPatch, kEntryBytes,
         {{kEntryPred, kEntryPredBytes}, {kEntryR13, kEntryR13Bytes}, {kEntryR14, kEntryR14Bytes}}, on_entry},
    };
}

bool all_bytes(const PointDef& d) {
    if (!bytes_at(d.rva, d.bytes)) return false;
    return std::all_of(d.ctx.begin(), d.ctx.end(), [](const Ctx& c) { return bytes_at(c.rva, c.bytes); });
}

bool install_point(const PointDef& d) {
    for (const Ctx& c : d.ctx) {
        if (!gad::in_real_code(g_secs, static_cast<uint32_t>(c.rva), static_cast<uint32_t>(c.bytes.size())) ||
            !bytes_at(c.rva, c.bytes)) {
            log::error("ObserverStage: {} REFUSED: the code it relies on at exe+0x{:X} ({} bytes) is not the expected "
                       ".rsrc code of build 2976",
                       kKindName[d.kind], c.rva, c.bytes.size());
            return false;
        }
    }
    return p8_install_mid(g_base, g_secs, d.rva, d.patch, d.bytes, d.fn, g_hooks[d.kind], "ObserverStage",
                          kKindName[d.kind]);
}

// 3527/3549 and 3576 (kDeleteBytes3527 unchanged).
void stage_thread_3527() {
    if (!read_sections()) {
        log::error("ObserverStage: the game's section table is unreadable; nothing is hooked");
        observer_scene_copy_disable("no section table");
        return;
    }
    const bool b3576 = game::current_build() == game::Build::v3576;
    const bool b3663 = game::current_build() == game::Build::v3663;
    const auto* profile = game::reader_profile();
    const uintptr_t world_slot = b3663   ? kWorldSlot3663
                                 : b3576 ? kWorldSlot3576
                                 : profile ? profile->world_system
                                           : 0;
    for (int i = 0; world_slot && i < 1200; ++i) {
        uintptr_t world = 0;
        if (peek(g_base + world_slot, world) && world) break;
        Sleep(500);
    }
    if (!observer_scene_copy_verify_current(g_base)) return;
    if (!p8_install_mid(g_base, g_secs, b3663 ? kDelete3663 : b3576 ? kDelete3576 : kDelete3527, kPatch5,
                        kDeleteBytes3527, on_delete_3527,
                        g_hooks[kKDelete], "ObserverStage", kKindName[kKDelete])) {
        observer_scene_copy_disable("the 2810 hook is not installed");
        return;
    }
    g_on.store(true);
    for (uint64_t tick = 1;; ++tick) {
        Sleep(1000);
        try {
            observer_scene_copy_drain();
        } catch (...) {
            log::error("ObserverSceneCopy: drain failed (allocation?); events kept in the ring");
        }
        if (tick % 60 == 0) {
            if (const std::string m = observer_scene_copy_counters(); !m.empty()) log::info("{}", m);
        }
    }
}

DWORD WINAPI stage_thread(LPVOID) {
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    if (game::current_build() == game::Build::v3527 || game::current_build() == game::Build::v3576 ||
        game::current_build() == game::Build::v3663) {
        stage_thread_3527();
        return 0;
    }
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (g_base != off::kImageBase || !peek(g_base, dos) || !peek(g_base + dos.e_lfanew, nt) ||
        nt.FileHeader.TimeDateStamp != off::kPeTimestamp) {
        log::error("ObserverStage: unsupported game build; observer_stage_sync stays off");
        return 0;
    }
    if (!read_sections()) {
        log::error("ObserverStage: the game's section table is unreadable; nothing is hooked");
        return 0;
    }
    const std::vector<PointDef> defs = points();
    g_wanted.store(static_cast<uint32_t>(defs.size()));
    for (int i = 0; i < 1200; ++i) {  // WorldSystem, as the P8 probes (up to 10 minutes)
        uintptr_t world = 0;
        if (peek(g_base + off::kWorldSystemSlot, world) && world) break;
        Sleep(500);
    }
    for (int i = 0; i < 24000; ++i) {  // the code (up to 2 minutes)
        if (std::all_of(defs.begin(), defs.end(), all_bytes)) break;
        Sleep(5);
    }
    // P8 S2: the milestone's code is compared BEFORE these hooks go in (one of them patches the
    // emitter's first bytes); off for the run if anything differs.
    if (observer_milestone_mode() != oms::Mode::Off) observer_milestone_verify(g_base, g_secs);
    // P8: the scene copy's code too (one of these hooks patches the 2810 serializer's first bytes).
    if (observer_scene_copy_wanted()) observer_scene_copy_verify(g_base, g_secs);
    std::string on, refused;
    bool entry_on = false, delete_on = false;
    for (const PointDef& d : defs) {
        const bool ok = install_point(d);
        if (ok) g_hooked.fetch_add(1);
        if (ok && d.kind == kKEntry) entry_on = true;
        if (ok && d.kind == kKDelete) delete_on = true;
        (ok ? on : refused) += std::format(" {} (exe+0x{:X})", kKindName[d.kind], d.rva);
    }
    if (!entry_on) observer_milestone_disable("the entry hook 0x2BC84E2 is not installed");
    if (!delete_on) observer_scene_copy_disable("the 2810 hook 0x2A4E4C0 is not installed");
    // P8 S1 (host_scene_diag.h): its own checked points, from this thread (nothing when s1_scene_diag=0).
    host_scene_diag_install(g_base, g_secs);
    g_install_us.store(p8_now_us());
    g_on.store(g_hooked.load() > 0);
    log::info("ObserverStage ON (observer_stage_sync, MEASURE ONLY, read only{}): hooked:{} | REFUSED:{} | nothing is "
              "sent and no game function is called (no native snapshot path, §5, and a byte replay is not coherent: "
              "pendientes/p8-observador-escenas.md Fase 2); lines: every 2661/2810/2322, 2981 up to {} per 5 s, every "
              "field entry, follow-ups +10/+60/+300 s after a non-owner entry; 'corr=op:actor:seq:value' tokens match "
              "the guest's GuestStage lines{}{}",
              g_send_refused.load() ? "; the SEND mode asked for is NOT implemented and was refused" : "",
              on.empty() ? " none" : on, refused.empty() ? " none" : refused, kPerWindow,
              !observer_milestone_active() ? ""
              : observer_milestone_mode() == oms::Mode::Send
                  ? " | its entry hook also hands each entry to observer_milestone (SEND: the native 2322 for an "
                    "observer, see the ObserverMilestone lines)"
                  : " | its entry hook also hands each entry to observer_milestone (dry run: decides and logs only)",
              observer_scene_copy_active() ? " | its 2810 hook also hands each 2810 to observer_scene_copy (a scene of "
                                             "user 2's closed toward another character gets the native 2810 for user "
                                             "2 too, see the ObserverSceneCopy lines)"
                                           : "");
    for (uint64_t tick = 1;; ++tick) {
        Sleep(1000);
        try {
            drain();
        } catch (...) {
            log::error("ObserverStage: drain failed (allocation?); events kept in the ring");
        }
        try {
            observer_milestone_drain();  // P8 S2: its lines and follow-ups (nothing when off)
        } catch (...) {
            log::error("ObserverMilestone: drain failed (allocation?); events kept in the ring");
        }
        try {
            observer_scene_copy_drain();  // P8: user 2's scenes (nothing when off)
        } catch (...) {
            log::error("ObserverSceneCopy: drain failed (allocation?); events kept in the ring");
        }
        host_scene_diag_drain();  // P8 S1: noexcept in effect (catches inside; nothing when off)
        if (tick % 60 == 0) {
            log::info("{}", counters());
            if (const std::string m = observer_milestone_counters(); !m.empty()) log::info("{}", m);
            if (const std::string m = observer_scene_copy_counters(); !m.empty()) log::info("{}", m);
        }
    }
}

}  // namespace

bool observer_stage_install(uint32_t ini_value) {
    const obs::ModeChoice m = obs::choose_mode(ini_value);
    if (m.mode == obs::Mode::Off) return false;
    if (m.send_refused) {
        g_send_refused.store(true);
        log::error("ObserverStage: observer_stage_sync={} asks to SEND the stage/sequencer snapshot to user 2; that mode "
                   "is NOT implemented: replaying the owner's exact 2661/2981 is not coherent (user 2's client routes "
                   "them to its own character's manager, 0xC0612A / 0x9A5BE0, while the NPCs they bind search the "
                   "host character's manager, 0x9ED290; every binding is type 5 and must already exist; the owner's "
                   "client drives these sequencers with C>S 2767/2591/2436 a second driver would duplicate: "
                   "pendientes/p8-observador-escenas.md Fase 2). Running as 1 (measure only). This key NEVER sends "
                   "anything, not even the 2322: the S2 experiment (the native 2322 for an observer) is "
                   "[session2] observer_milestone_send=1 (pendientes/p8-2322-observador.md)",
                   ini_value);
    }
    if (g_started.exchange(true)) return true;
    CloseHandle(CreateThread(nullptr, 0, stage_thread, nullptr, 0, nullptr));
    return true;
}

bool observer_stage_active() { return g_started.load(); }

std::string observer_stage_describe() {
    if (!g_started.load()) return {};
    return std::format("ObserverStage {} hooked {}/{} live sequencers {} entries {} (observer {})",
                       g_on.load() ? "on" : "starting", g_hooked.load(), g_wanted.load(), g_live.load(),
                       g_entries.load(), g_observer_entries.load());
}

}  // namespace cdmp::session2
