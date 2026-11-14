#pragma once
// P8 session 12/13, the shopkeepers (docs/research/pendientes/p8-impl-tenderos-c1.md): pure logic shared by the
// guest's C1 redirect (guest_x_interaction.h) and the host's shop probe (shop_probe.h). No game call, no allocation.
//
// 1. A read-only replica of the sequencer lookup 0x1F6C190(mgr, &out, u64 id) (build 1.0.0.2976, common to the
//    client's and the server's stage managers; read with capstone, p8-impl-tenderos-c1.md §2):
//      [mgr+0x10C] u32 element count (0 -> not found)
//      [mgr+0x108] u32 bucket count  (0 -> not found)
//      h = 0x1364780(&id, 8)          lookup3 hashlittle over the 8 bytes of the u64 id, initval 0xC5EDE
//                                     (lea ebx,[rdx-0x2145E233]: a = b = c = 0xDEBA1DCD + 8; jump-table case 8:
//                                     b += k[1], a += k[0], then the final mix; returns c)
//      bucket = [mgr+0x118] + (h % buckets) * 0x100: u32 n at +0, then n pairs {u32 hash, u32 index} from +8
//      element = [[mgr+0x120] + index * 8]: its u64 [+8] must be the id; the instance is [element+0x10]
//      an instance whose byte [+0x15] is set counts as not found (0x1F6C240: the "dead" flag)
//    The game takes [mgr+8]'s lock around it; the replica reads without it (SEH reads in the hooks): a table being
//    rebuilt at that moment gives "not found" or a stale answer, never a write.
// 2. IdBook: "the first K events of each id" for the log lines, lock-free (any game thread).

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace cdmp::session2::isl {

// ---------------------------------------------------------------- the id hash (0x1364780 for 8 bytes)

inline constexpr uint32_t kIdHashInit = 0xC5EDE;  // 0xDEBA1DCD - 0xDEADBEEF (lookup3's base)
inline constexpr uint32_t rotl(uint32_t x, int k) { return (x << k) | (x >> (32 - k)); }

// lookup3 hashlittle of the 8 little-endian bytes of id with initval 0xC5EDE: no CRT, no loop (hook-safe).
inline constexpr uint32_t hash_id(uint64_t id) {
    uint32_t a = 0xDEADBEEFu + 8u + kIdHashInit, b = a, c = a;
    b += static_cast<uint32_t>(id >> 32);
    a += static_cast<uint32_t>(id);
    c ^= b; c -= rotl(b, 14);
    a ^= c; a -= rotl(c, 11);
    b ^= a; b -= rotl(a, 25);
    c ^= b; c -= rotl(b, 16);
    a ^= c; a -= rotl(c, 4);
    b ^= a; b -= rotl(a, 14);
    c ^= b; c -= rotl(b, 24);
    return c;
}

// ---------------------------------------------------------------- the table walk

inline constexpr uint32_t kMgr_Buckets = 0x108, kMgr_Count = 0x10C, kMgr_BucketArray = 0x118, kMgr_Elements = 0x120;
// Where the manager keeps its table, per build. 3527 / 3549: the same walk in 0x2156CA0 with every offset +0x28
// (count +0x134, buckets +0x130, bucket array +0x140, elements +0x148; the hash 0x1546830 is the same lookup3 with
// lea ebx,[rdx-0x2145E233]; element +8 the id, +0x10 the instance, +0x15 dead), capstone 2026-11-06.
struct MgrLayout {
    uint32_t buckets, count, bucket_array, elements;
};
inline constexpr MgrLayout kLayout2976{kMgr_Buckets, kMgr_Count, kMgr_BucketArray, kMgr_Elements};
inline constexpr MgrLayout kLayout3527{0x130, 0x134, 0x140, 0x148};
inline constexpr uint32_t kBucketStride = 0x100, kBucketPairs = (kBucketStride - 8) / 8;  // 31 pairs fit a bucket
inline constexpr uint32_t kElem_Id = 0x08, kElem_Inst = 0x10, kInst_Dead = 0x15;
inline constexpr uint32_t kMaxIndex = 1u << 20;  // a sane element index (the game has hundreds)

struct Lookup {
    bool read_ok = false;  // every read the walk needed succeeded
    bool found = false;    // an element with the id and a live instance (what 0x1F6C190 returns non-null)
    bool dead = false;     // the element exists but its instance is flagged dead (+0x15): 0x1F6C190 returns null
    uintptr_t inst = 0;    // the instance (found or dead)
    uint32_t hash = 0;
    uint32_t count = 0;    // [mgr+0x10C]
};

// Rd: an object with `template <class T> bool rd(uintptr_t addr, T& out) const` (SEH reads in the mod, a fake
// memory in the tests). Mirrors 0x1F6C190 step by step.
template <class Rd>
Lookup find_stage(const Rd& m, uintptr_t mgr, uint64_t id, const MgrLayout& lay = kLayout2976) {
    Lookup r;
    r.hash = hash_id(id);
    if (!mgr) return r;
    uint32_t count = 0, buckets = 0;
    if (!m.rd(mgr + lay.count, count)) return r;
    r.count = count;
    if (count == 0) {
        r.read_ok = true;
        return r;
    }
    if (!m.rd(mgr + lay.buckets, buckets)) return r;
    if (buckets == 0) {
        r.read_ok = true;
        return r;
    }
    uintptr_t barr = 0, elems = 0;
    if (!m.rd(mgr + lay.bucket_array, barr) || !m.rd(mgr + lay.elements, elems) || !barr || !elems) return r;
    const uintptr_t bucket = barr + static_cast<uintptr_t>(r.hash % buckets) * kBucketStride;
    uint32_t n = 0;
    if (!m.rd(bucket, n)) return r;
    if (n > kBucketPairs) n = kBucketPairs;
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t h = 0, idx = 0;
        if (!m.rd(bucket + 8 + 8 * static_cast<uintptr_t>(i), h)) return r;
        if (h != r.hash) continue;
        if (!m.rd(bucket + 0xC + 8 * static_cast<uintptr_t>(i), idx) || idx >= kMaxIndex) return r;
        uintptr_t elem = 0;
        uint64_t eid = 0;
        if (!m.rd(elems + 8 * static_cast<uintptr_t>(idx), elem) || !elem || !m.rd(elem + kElem_Id, eid)) return r;
        if (eid != id) continue;
        uintptr_t inst = 0;
        if (!m.rd(elem + kElem_Inst, inst)) return r;
        r.read_ok = true;
        r.inst = inst;
        if (!inst) return r;
        uint8_t dead = 0;
        if (!m.rd(inst + kInst_Dead, dead)) {
            r.read_ok = false;
            return r;
        }
        r.dead = dead != 0;
        r.found = !r.dead;
        return r;
    }
    r.read_ok = true;
    return r;
}

// ---------------------------------------------------------------- the first K events of each id

// A fixed table of ids (0 = a free slot), claimed with a CAS; `take` says whether this event is among the first
// `k` of its id. A full table answers false (the caller's window limiter and counters still see the event).
template <size_t N>
class IdBook {
public:
    bool take(uint64_t id, uint32_t k) {
        if (id == 0) return false;
        for (size_t i = 0; i < N; ++i) {
            uint64_t cur = ids_[i].load(std::memory_order_acquire);
            if (cur == 0) {
                uint64_t expected = 0;
                if (ids_[i].compare_exchange_strong(expected, id, std::memory_order_acq_rel)) {
                    cur = id;
                } else {
                    cur = expected;
                }
            }
            if (cur == id) return counts_[i].fetch_add(1, std::memory_order_relaxed) < k;
        }
        full_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    uint64_t count_of(uint64_t id) const {
        for (size_t i = 0; i < N; ++i) {
            if (ids_[i].load(std::memory_order_acquire) == id) return counts_[i].load(std::memory_order_relaxed);
        }
        return 0;
    }
    size_t used() const {
        size_t n = 0;
        for (size_t i = 0; i < N; ++i) n += ids_[i].load(std::memory_order_relaxed) != 0;
        return n;
    }
    uint64_t id_at(size_t i) const { return i < N ? ids_[i].load(std::memory_order_acquire) : 0; }
    uint64_t count_at(size_t i) const { return i < N ? counts_[i].load(std::memory_order_relaxed) : 0; }
    uint64_t full() const { return full_.load(std::memory_order_relaxed); }
    static constexpr size_t capacity() { return N; }

private:
    std::atomic<uint64_t> ids_[N] = {};
    std::atomic<uint64_t> counts_[N] = {};
    std::atomic<uint64_t> full_{0};
};

// ---------------------------------------------------------------- the points in 0x2126920 (both sides)

// 0x2126920(entry, J) = the condition of a dynamic interaction entry (p8-s12-tenderos.md §4.2): RCX = the entry
// (kept in R13), RDX = J (R15). Read with capstone on the read-only PE (build 2976, .rsrc, RUNTIME_FUNCTION
// 0x2126920-0x2126D3C; no branch of the function and no rel32 call/jmp of the PE lands strictly inside a patch).
//   A 0x2126A1F  mov rdi,rax ; mov [rbp+0x8E8],rax       RAX = field.vf48 = the stage manager the lookup will use;
//                (10 bytes)                              the field at [rsp+0x48]; then vf40, the lock of [rdi+8]
//                                                        (0x393DF0 at 0x2126A56) and 0x1F6C190(rdi, &out, [r13+0x20])
//                                                        at 0x2126A6A. Every later use of the manager reads rdi /
//                                                        [rbp+0x8E8] (0x1F6FC40 at 0x2126AD0), so RAX := X here
//                                                        makes the lookup, its lock and the dead check use X alike.
//   R 0x2126AAB  lea rcx,[rbp+0x8D0]                     after the lookup (both paths join here): RSI = the stage
//                (7 bytes; a je target at its start)     instance found or 0, [rbp+0x8E8] = the manager used.
//   F 0x2126D11  mov [rbp-0x80],rdi ; lea rcx,[rbp-0x80] every path but the two early returns (no stage id: al = 2;
//                (8 bytes; a jmp target at its start)    no user: al = 0) reaches it with BL = the result (0 refused,
//                                                        1 / 2 accepted: 0x2126C6F..0x2126C77, 0x2126C88 xor bl).
inline constexpr uintptr_t kPointA = 0x2126A1F, kPointR = 0x2126AAB, kPointF = 0x2126D11;
inline constexpr uint32_t kPatchA = 10, kPatchR = 7, kPatchF = 8;
inline constexpr uint8_t kBytesA[] = {0x48, 0x8B, 0xF8, 0x48, 0x89, 0x85, 0xE8, 0x08, 0x00, 0x00};
inline constexpr uint8_t kBytesR[] = {0x48, 0x8D, 0x8D, 0xD0, 0x08, 0x00, 0x00};
inline constexpr uint8_t kBytesF[] = {0x48, 0x89, 0x7D, 0x80, 0x48, 0x8D, 0x4D, 0x80};
// Context checked before A (the vf48 call and its field slot) and before R (the lookup's call and its result use):
//   0x2126A14 mov rcx,[rsp+0x48] ; mov rax,[rcx] ; call [rax+0x48]
//   0x2126A5C mov r8,[r13+0x20] ; lea rdx,[rbp+0x8D0] ; mov rcx,rdi ; call 0x1F6C190 (rel32 E8 21 57 E4 FF)
inline constexpr uintptr_t kCtxA = 0x2126A14, kCtxLookup = 0x2126A5C;
inline constexpr uint8_t kCtxABytes[] = {0x48, 0x8B, 0x4C, 0x24, 0x48, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48};
inline constexpr uint8_t kCtxLookupBytes[] = {0x4D, 0x8B, 0x45, 0x20, 0x48, 0x8D, 0x95, 0xD0, 0x08, 0x00, 0x00,
                                              0x48, 0x8B, 0xCF, 0xE8, 0x21, 0x57, 0xE4, 0xFF};
inline constexpr uint32_t kRspField = 0x48;     // [rsp+0x48] at A: the field whose vf48 gave RAX
inline constexpr uint32_t kRbpMgrUsed = 0x8E8;  // [rbp+0x8E8] after A: the manager the lookup used
inline constexpr uint32_t kEntry_StageId = 0x20;  // u64 [entry+0x20] (0x2126A5C), tested & 0x1FFFFFFF at 0x212694D
inline constexpr uint32_t kJ_User = 0xA0, kUser_Key = 0x60;

// Builds 3527 / 3549 (same code; capstone on the 3549 PE, 2026-11-06): the function is 0x22ED620 (RUNTIME_FUNCTION
// 0x22ED620-0x22EDA76): rcx = the entry (r13), rdx = J (r15), the stage id test [rcx+0x20] & 0x1FFFFFFF at 0x22ED64D.
//   A 0x22ED729  mov rdi,rax ; mov [rbp+0x8F8],rax  after field.vf48 (0x22ED71E: mov rcx,[rsp+0x48] ; mov rax,[rcx] ;
//                (10 bytes)                         call [rax+0x48]); then vf40, the lock of [rdi+8] (0x3E4100 at
//                                                   0x22ED760) and 0x2156CA0(rdi, &out [rbp+0x8F0], [r13+0x20]) at
//                                                   0x22ED774; the dead check 0x215A5F0 reads [rbp+0x8F8] (0x22ED7DA).
//   R 0x22ED7B5  lea rcx,[rbp+0x8F0]                both paths of the lookup join here (a je target at its start):
//                (7 bytes)                          RSI = the instance found or 0, [rbp+0x8F8] = the manager used.
//   F 0x22EDA49  mov [rsp+0x70],rdi ; lea rcx,[rsp+0x70]  every path but the two early returns (no stage id: al = 2,
//                (10 bytes; a jmp target at start)  straight to 0x22EDA5B) reaches it with BL = the result; r13 and
//                                                   rsp are those of the entry (no push in the body).
inline constexpr uintptr_t kPointA3527 = 0x22ED729, kPointR3527 = 0x22ED7B5, kPointF3527 = 0x22EDA49;
// F's first instruction is already 5 bytes: safetyhook relocates only it (live 2026-11-06: a 10-byte patch was refused).
inline constexpr uint32_t kPatchA3527 = 10, kPatchR3527 = 7, kPatchF3527 = 5;
inline constexpr uint8_t kBytesA3527[] = {0x48, 0x8B, 0xF8, 0x48, 0x89, 0x85, 0xF8, 0x08, 0x00, 0x00};
inline constexpr uint8_t kBytesR3527[] = {0x48, 0x8D, 0x8D, 0xF0, 0x08, 0x00, 0x00};
inline constexpr uint8_t kBytesF3527[] = {0x48, 0x89, 0x7C, 0x24, 0x70, 0x48, 0x8D, 0x4C, 0x24, 0x70};
inline constexpr uintptr_t kCtxA3527 = 0x22ED71E, kCtxLookup3527 = 0x22ED766;
inline constexpr uint8_t kCtxABytes3527[] = {0x48, 0x8B, 0x4C, 0x24, 0x48, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x48};
inline constexpr uint8_t kCtxLookupBytes3527[] = {0x4D, 0x8B, 0x45, 0x20, 0x48, 0x8D, 0x95, 0xF0, 0x08, 0x00, 0x00,
                                                  0x48, 0x8B, 0xCF, 0xE8, 0x27, 0x95, 0xE6, 0xFF};
inline constexpr uint32_t kRbpMgrUsed3527 = 0x8F8;
inline constexpr uintptr_t kVtClientField3527 = 0x594BA50;    // pa::ClientField (rtti_3527.json; vf48 0xAAA7A0)
inline constexpr uintptr_t kVtClientStageMgr3527 = 0x59572E0;  // pa::ClientSequencerStageManager

// Build 3576 (static, 2026-11-06 evening; not yet run): the same function, moved as one block to 0x22EE2D0
// (+0xCB0; RUNTIME_FUNCTION 0x22EE2D0-0x22EE726, the same 0x456 bytes), its five points unique there with the same
// bytes but the lookup call's rel32; the lookup 0x21578E0 reads the manager's +0x134 / +0x130 / +0x140 as in 3527.
inline constexpr uintptr_t kPointA3576 = 0x22EE3D9, kPointR3576 = 0x22EE465, kPointF3576 = 0x22EE6F9;
inline constexpr uintptr_t kCtxA3576 = 0x22EE3CE, kCtxLookup3576 = 0x22EE416;
inline constexpr uint8_t kCtxLookupBytes3576[] = {0x4D, 0x8B, 0x45, 0x20, 0x48, 0x8D, 0x95, 0xF0, 0x08, 0x00, 0x00,
                                                  0x48, 0x8B, 0xCF, 0xE8, 0xB7, 0x94, 0xE6, 0xFF};
inline constexpr uintptr_t kVtClientField3576 = 0x594DB40;    // pa::ClientField (vtable_map_3549_3576.json)
inline constexpr uintptr_t kVtClientStageMgr3576 = 0x5959438;  // pa::ClientSequencerStageManager

// Build 1.0.0.3663 (static, 2026-11-13): guest_x_interaction.cpp holds its own table (kPoints3663: the function at
// 0x235EB60, R's out slot +0x8E0, the manager's map at +0x138/+0x13C/+0x148/+0x150, every offset +8 from 3527's;
// pa::ClientField 0x59C97C0, pa::ClientSequencerStageManager 0x59D57E8). Nothing else here is build-specific: the
// other users of this header (shop_probe, shop_trade_probe, user2_shops) are 2976-only and keep kLayout2976.

// RTTI vtables (build 2976).
inline constexpr uintptr_t kVtClientField = 0x55BCEA0;    // pa::ClientField (vf48 0x9A5BE0)
inline constexpr uintptr_t kVtServerField = 0x5B29A60;    // pa::ServerField (vf48 0x2B00CE0)
inline constexpr uintptr_t kVtClientStageMgr = 0x55C9720;  // pa::ClientSequencerStageManager
inline constexpr uintptr_t kVtServerStageMgr = 0x5B17A58;  // pa::ServerSequencerStageManager

}  // namespace cdmp::session2::isl
