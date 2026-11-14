#include "mod/session2/interaction_condition.h"

#include <windows.h>
#include <safetyhook.hpp>

#include <array>
#include <atomic>
#include <cstring>
#include <format>

#include "mod/game/build_profile.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"

namespace cdmp::session2 {
namespace {

// Confirmed by the exception return slot in host_fault_62480_native.json.
// The caller uses RSI=component, RDI=entry, RBX=archive. The mid hook runs
// after loading RCX=[RDI+8], immediately before the native serializer call.
constexpr uintptr_t kCall = 0x22E2657;
constexpr uintptr_t kServerInteractionVtable = 0x5EF21D0;
constexpr uint8_t kCallBytes[] = {
    0x48, 0x8B, 0x4F, 0x08, 0x48, 0x8B, 0xD3, 0xE8, 0xD4, 0x1B, 0x1B, 0x00,
    0x0F, 0xB7, 0x57, 0x10, 0xE8, 0xAB, 0xC5, 0x0F, 0xFE};
constexpr uint8_t kSerializerHead[] = {
    0x48, 0x89, 0x5C, 0x24, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x20,
    0x48, 0x83, 0x39, 0x00, 0x48, 0x8B, 0xDA, 0x48, 0x8B, 0x02,
    0x48, 0x8B, 0xF9, 0x41, 0xB8, 0x01, 0x00, 0x00, 0x00,
    0x48, 0x8D, 0x54, 0x24, 0x30, 0x48, 0x8B, 0xCB,
    0x0F, 0x95, 0x44, 0x24, 0x30, 0xFF, 0x50, 0x08,
    0x80, 0x7C, 0x24, 0x30, 0x00, 0x74, 0x6F};
constexpr uint8_t kSerializerReturn[] = {
    0x48, 0x8B, 0x5C, 0x24, 0x40, 0x48, 0x83, 0xC4, 0x20, 0x5F, 0xC3};
// Build 1.0.0.3576 (static, 2026-11-06; not yet run). ServerInteraction vtable 0x5EF21D0 -> 0x5EF4338 (RTTI map); its
// slot +0xC8 is the method 0x22E25F0 -> 0x22E32A0 (+0xCB0, same .pdata size 0x1F1, still RSI = component, RDI = entry
// with stride 0x38 from [+0x90] / [+0x98], RBX = archive). The call site 0x22E2657 -> 0x22E3307; its two rel32s changed
// (serializer 0x2494230 -> 0x2495000, +0xDD0, head and return bytes unchanged; 0x3DEC10 -> 0x3DEEF0).
constexpr uint8_t kCallBytes3576[] = {  // 0x22E3300
    0x48, 0x8B, 0x4F, 0x08, 0x48, 0x8B, 0xD3, 0xE8, 0xF4, 0x1C, 0x1B, 0x00,
    0x0F, 0xB7, 0x57, 0x10, 0xE8, 0xDB, 0xBB, 0x0F, 0xFE};
// Build 1.0.0.3663 (static, 2026-11-13; never run). ServerInteraction vtable 0x5EF4338 -> 0x5F6DE10 (RTTI map); its
// slot +0xC8 is the method 0x2353AE0 (3527's 0x22E25F0 + 0x714F0, .pdata 0x1F2 bytes; still RSI = component, RDI = entry
// with stride 0x38 from [+0x90] / [+0x98] at 0x2353B18, RBX = archive). The call site 0x22E2657 -> 0x2353B47 (+0x67 as
// on 3527): `mov rcx,[rdi+8] ; mov rdx,rbx ; call 0x2506E70` with 3527's bytes but the rel32, then the entry's +0x10 is
// now passed by address (`lea rcx,[rdi+0x10] ; call 0x3DAD70`, 3527 `movzx edx,word [rdi+0x10] ; call 0x3DEC10`); the
// entry fields the method serializes (+8/+0x10/+0x20/+0x28/+0x30/+0x18/+0x14/+0x2C) keep their offsets. The serializer
// 0x2494230 -> 0x2506E70 (+0x72C40; head and return bytes unchanged). What the rule reads keeps 3527's code: derived
// entries get +0x2E = parent index (0x235C721), +8 null, +0x20 stage 0; the copy skips empty strings (0x235E503); the
// shared string keeps chars +0 / length +8 (0x16450AF / 0x16450C1).
constexpr uint8_t kCallBytes3663[] = {  // 0x2353B40
    0x48, 0x8B, 0x4F, 0x08, 0x48, 0x8B, 0xD3, 0xE8, 0x24, 0x33, 0x1B, 0x00,
    0x48, 0x8D, 0x4F, 0x10, 0xE8, 0x1B, 0x72, 0x08, 0xFE};

struct Sites {
    uintptr_t call, vtable, method, serializer;
    const uint8_t (&call_bytes)[sizeof kCallBytes];
};
const Sites kSites3527{kCall, kServerInteractionVtable, 0x22E25F0, 0x2494230, kCallBytes};
const Sites kSites3576{0x22E3307, 0x5EF4338, 0x22E32A0, 0x2495000, kCallBytes3576};
const Sites kSites3663{0x2353B47, 0x5F6DE10, 0x2353AE0, 0x2506E70, kCallBytes3663};
const Sites* g_sites = &kSites3527;

// Native 2494230 reads only the first pointer on its empty path, emits one
// zero presence byte through archive vf8, and returns. It never owns or
// mutates this holder. Static const storage also makes concurrent calls safe.
alignas(16) constexpr std::array<uint64_t, 2> kEmptyCondition{};
SafetyHookMid g_hook;
uintptr_t g_base = 0;
std::atomic<uint64_t> g_empty_encoded{0}, g_unrecognized_null{0};

template <class T>
bool read_at(uintptr_t address, T& value) noexcept {
    return address && game::safe_read(address, &value, sizeof value);
}

template <class T>
T field(const std::array<uint8_t, 0x38>& entry, size_t offset) noexcept {
    T value{};
    std::memcpy(&value, entry.data() + offset, sizeof value);
    return value;
}

bool component_entry(uintptr_t component, uintptr_t entry) noexcept {
    uintptr_t vt = 0, data = 0;
    uint32_t count = 0;
    return read_at(component, vt) && vt == g_base + g_sites->vtable &&
           read_at(component + 0x90, data) && data &&
           read_at(component + 0x98, count) && count && count <= 0xFFFF &&
           entry >= data && (entry - data) / 0x38 < count && (entry - data) % 0x38 == 0;
}

void serialize_condition(SafetyHookContext& ctx) {
    if (ctx.rcx) return;
    if (component_entry(ctx.rsi, ctx.rdi)) {
        const uintptr_t replacement = interaction_condition_argument(0, ctx.rdi);
        if (replacement) {
            ctx.rcx = replacement;
            g_empty_encoded.fetch_add(1, std::memory_order_relaxed);
            return;
        }
    }
    g_unrecognized_null.fetch_add(1, std::memory_order_relaxed);
}

template <size_t N>
bool code_matches(uintptr_t rva, const uint8_t (&expected)[N]) {
    std::array<uint8_t, N> actual{};
    return game::safe_read(g_base + rva, actual.data(), actual.size()) &&
           std::memcmp(actual.data(), expected, N) == 0;
}

}  // namespace

uintptr_t interaction_condition_argument(uintptr_t holder, uintptr_t entry) noexcept {
    if (holder) return holder;
    std::array<uint8_t, 0x38> bytes{};
    if (!entry || !game::safe_read(entry, bytes.data(), bytes.size()) ||
        field<uintptr_t>(bytes, 8) != 0 ||
        (field<uint32_t>(bytes, 0x20) & 0x1FFFFFFF) != 0 ||
        field<uint16_t>(bytes, 0x2E) == 0xFFFF) return holder;

    // Native derived entries (22EB150..22EB1ED) have an empty condition
    // string, no stage, and a parent InteractionInfo index at +2E. The parent
    // is a resource index, NOT an index into this component's vector.
    // Stage-linked nulls are deliberately excluded: their evaluation rules
    // differ. Stage-less entries return before inspecting the condition.
    const uintptr_t string = field<uintptr_t>(bytes, 0);
    uintptr_t chars = 0;
    uint32_t length = 0;
    uint8_t first = 0xFF;
    if (!read_at(string, chars) || !chars || !read_at(string + 8, length) || length ||
        !read_at(chars, first) || first) return holder;
    return reinterpret_cast<uintptr_t>(kEmptyCondition.data());
}

bool interaction_condition_install() {
    if (game::current_build() == game::Build::v2976) return true;
    const game::Build build = game::current_build();
    if (build != game::Build::v3527 && build != game::Build::v3576 && build != game::Build::v3663) return false;
    if (g_hook) return true;
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    g_sites = build == game::Build::v3663   ? &kSites3663
              : build == game::Build::v3576 ? &kSites3576
                                            : &kSites3527;
    uintptr_t method = 0;
    if (!code_matches(g_sites->call - 7, g_sites->call_bytes) ||
        !code_matches(g_sites->serializer, kSerializerHead) ||
        !code_matches(g_sites->serializer + 0xA3, kSerializerReturn) ||
        !read_at(g_base + g_sites->vtable + 0xC8, method) ||
        method != g_base + g_sites->method) {
        log::error("Session2: interaction condition serializer signature mismatch; tunnel stays closed");
        return false;
    }
    g_hook = safetyhook::create_mid(reinterpret_cast<void*>(g_base + g_sites->call), &serialize_condition);
    if (!g_hook) {
        log::error("Session2: cannot install interaction condition serializer fix; tunnel stays closed");
        return false;
    }
    log::info("Session2 interaction condition fix ON: native stage-less derived interactions with no "
              "condition serialize the native empty marker at exe+0x{:X}; actor state is unchanged",
              g_sites->call);
    return true;
}

std::string interaction_condition_describe() {
    return std::format("interaction empty conditions {} (unrecognized null {})",
                       g_empty_encoded.load(), g_unrecognized_null.load());
}

}  // namespace cdmp::session2
