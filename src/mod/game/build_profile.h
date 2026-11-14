#pragma once
// Build identity and the reader addresses verified for that executable.
// This does not authorize legacy hooks: each hook needs its own verified profile.

#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <string_view>

#include "common/native_opcode.h"
#include "mod/game/offsets.h"
#include "mod/game/safe_memory.h"

namespace cdmp::game {

using Build = native_opcode::Build;

inline constexpr uint32_t kPeTimestamp3527 = 0x6AEA07A6, kImageSize3527 = 0x13EB2000;
inline constexpr uint32_t kPeTimestamp3549 = 0x6AEB7D59, kImageSize3549 = 0x13CFF000;
// 1.0.0.3576 (Steam, 2026-11-06 18:37): a new layout. Every vtable moved (by name: 15,716 of 15,717,
// tools/porting/data/vtable_map_3549_3576.json), the code grew and shifted (+0x4A000 .. +0x312000), the Troc catalogue
// is unchanged. Each module needs its own port to it (docs/research/port-3576.md); until then it refuses it.
inline constexpr uint32_t kPeTimestamp3576 = 0x6AED2E85, kImageSize3576 = 0x13CC4000;
// 1.0.0.3663 (Steam, 2026-11-13 ~19:28): another new layout (vtables +0x79000..+0x7E000, code shifted, globals
// +0x85000) and a RENUMBERED Troc catalogue (native_opcode.h). docs/research/port-3663.md. Nothing ported yet: every
// module refuses it (their gates admit only the builds they carry tables for).
inline constexpr uint32_t kPeTimestamp3663 = 0x6AF5D198, kImageSize3663 = 0x144E9000;

// The running exe's PE identity; zero if it is not a 64-bit image at the game's fixed base.
struct PeIdentity {
    uint32_t timestamp = 0, image_size = 0;
};
inline PeIdentity pe_identity() noexcept {
    static const PeIdentity identity = [] {
        const auto base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
        if (base != build_2976::kImageBase) return PeIdentity{};
        const auto dos = read<IMAGE_DOS_HEADER>(base);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0x40 ||
            dos->e_lfanew > 0x100000) return PeIdentity{};
        const auto nt = read<IMAGE_NT_HEADERS64>(base + dos->e_lfanew);
        if (!nt || nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
            nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
            nt->OptionalHeader.ImageBase != base) return PeIdentity{};
        return PeIdentity{nt->FileHeader.TimeDateStamp, nt->OptionalHeader.SizeOfImage};
    }();
    return identity;
}

// 1.0.0.3549 (the update of 2026-11-05) keeps 3527's layout, so Build::v3527 means both. Static comparison with what was
// saved of 3527: all 15,717 vtables, the code section .pdata count, the Troc catalogue and the globals are at the same
// addresses. Only the protected RWX section was re-encoded and relocated (it shrank by 0x1B3400 bytes), so what points
// into it differs: each thunk's rel32 and a few return addresses. Those few tables ask is_3549() (docs/ESTADO-3527.md).
inline bool is_3549() noexcept {
    const PeIdentity id = pe_identity();
    return id.timestamp == kPeTimestamp3549 && id.image_size == kImageSize3549;
}

inline bool is_3576() noexcept {
    const PeIdentity id = pe_identity();
    return id.timestamp == kPeTimestamp3576 && id.image_size == kImageSize3576;
}

inline bool is_3663() noexcept {
    const PeIdentity id = pe_identity();
    return id.timestamp == kPeTimestamp3663 && id.image_size == kImageSize3663;
}

inline Build current_build() noexcept {
    const PeIdentity id = pe_identity();
    if (id.timestamp == build_2976::kPeTimestamp) return Build::v2976;
    if ((id.timestamp == kPeTimestamp3527 && id.image_size == kImageSize3527) || is_3549()) return Build::v3527;
    if (is_3576()) return Build::v3576;
    if (is_3663()) return Build::v3663;
    return Build::unsupported;
}

// The builds the older modules carry tables for (2976, and 3527 with 3549). A module not ported to a newer build gates on
// this, so it refuses that build instead of falling through to its 2976 tables.
inline bool legacy_layout() noexcept {
    const Build b = current_build();
    return b == Build::v2976 || b == Build::v3527;
}

// 3527's object layout and protocol (3527, 3549 and 3576): the struct offsets the readers use and the native payloads.
// Not an address table: each module still needs its own 3576 addresses before it admits 3576.
inline bool layout_3527() noexcept {
    const Build b = current_build();
    return b == Build::v3527 || b == Build::v3576;
}

// The build whose native payload layout applies (common/movement_layout.h). Build 1.0.0.3576 (static, 2026-11-06):
// the Troc catalogue is 3527's with 0 opcode and 0 size changes (troc_mapping_3549_3576.json,
// opcode_mapping_3549_3576.json), so its payloads are read and written as 3527's.
// Build 1.0.0.3663 (static, 2026-11-13; never run): opcodes renumbered (native_opcode.h) but the payload READERS are
// 3527's: every function of tools/porting/data/payload_*_3527.txt, compared instruction by instruction with relative
// operands masked, is the same in 3663 (the handlers by their Troc vtable's slot 2, troc_mapping_3576_3663.json; the
// helpers by the calls at the same offsets): MoveActorReq 0x2C52CD0, MoveActorAck 0xCA8AB0, StartActionReq 0x2C46FA0,
// StartActionAck 0xC9CA10 (these three differ only in their jump-table bases), MoveFieldAck 0xCD4D70,
// LoadingFieldDataAck 0xCD6E00 (entry stride 56), MainPlayerDataStartAck 0xCB72E0; MoveData 0x26A8CE0, StartAction
// A/B 0x26A6F70 / 0x26A7570, Path 0x14CB240 / 0x14CB150, Transform 0x1644720, quaternion 0x1644640, the stream read
// 0x1643CD0 (data +0x20, length +0x28, cursor +0x2C), the MoveField entry 0x26AB5D0. So its payloads are 3527's.
inline Build wire_build() noexcept {
    const Build b = current_build();
    return b == Build::v3576 || b == Build::v3663 ? Build::v3527 : b;
}

inline Build native_build() noexcept { return current_build(); }

// Verify the loaded immutable singleton catalog before enabling native hooks.
// Cache only success: a caller before static initialization may safely retry.
inline bool validate_native_catalog() noexcept {
    static std::atomic<bool> validated{false};
    if (validated.load(std::memory_order_acquire)) return true;
    const auto build = current_build();
    const auto catalog = native_opcode::entries(build);
    constexpr size_t kMaxCatalog = 1200;  // 1175 messages in 3527/3576, 1179 in 3663
    if (catalog.empty() || catalog.size() > kMaxCatalog) return false;
    const auto base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    // The singleton block (troc_mapping_*.json instance_range); 3576's moved by +0x2000, 3663's
    // (troc_mapping_3576_3663.json) is 0x6F14E10..0x6F48840.
    const uintptr_t begin = build == Build::v3663   ? 0x6F14E10
                            : build == Build::v3576 ? 0x6E90D10
                            : build == Build::v3527 ? 0x6E8ED10
                                                    : 0x6A51AE0;
    const uintptr_t end = build == Build::v3663   ? 0x6F48840
                          : build == Build::v3576 ? 0x6EC4400
                          : build == Build::v3527 ? 0x6EC2400
                                                  : 0x6A82C80;
    const uintptr_t image_limit = build == Build::v3663   ? kImageSize3663
                                  : build == Build::v3576 ? kImageSize3576
                                  : build == Build::v3527 ? 0x13EB2000
                                                          : 0x10000000;
    std::array<bool, kMaxCatalog> seen{};
    size_t count = 0;
    for (uintptr_t addr = base + begin; addr < base + end; addr += 8) {
        const auto vt = read<uintptr_t>(addr);
        if (!vt) return false;
        if (*vt < base + 8 || *vt >= base + image_limit) continue;
        const auto col = read<uintptr_t>(*vt - 8);
        if (!col || *col < base || *col + 0x18 >= base + image_limit) continue;
        const auto signature = read<uint32_t>(*col);
        const auto td = read<uint32_t>(*col + 0x0C);
        if (!signature || *signature != 1 || !td || *td + 0x110ull >= image_limit) continue;
        char name[256]{};
        if (!safe_read(base + *td + 0x10, name, sizeof name - 1)) return false;
        const std::string_view decorated{name};
        constexpr std::string_view prefix = ".?AVTrocTr";
        if (!decorated.starts_with(prefix)) continue;
        const auto at = decorated.find('@', prefix.size());
        if (at == std::string_view::npos || decorated.substr(at) != "@pa@@") return false;
        const auto kind = read<uint32_t>(addr + 8);
        const auto opcode = read<uint16_t>(addr + 0x0C);
        if (!kind || !opcode) return false;
        const auto entry = std::lower_bound(catalog.begin(), catalog.end(), *opcode,
            [](const native_opcode::Entry& e, uint16_t op) { return e.native < op; });
        if (entry == catalog.end() || entry->native != *opcode || entry->kind != *kind ||
            entry->name != decorated.substr(prefix.size(), at - prefix.size())) return false;
        const size_t index = static_cast<size_t>(entry - catalog.begin());
        if (seen[index]) return false;
        seen[index] = true;
        ++count;
        addr += 0x88; // Each singleton occupies 0x90 bytes.
    }
    if (count != catalog.size()) return false;
    validated.store(true, std::memory_order_release);
    return true;
}

struct ReaderProfile {
    Build build;
    const char* version;
    uintptr_t world_system, chunk_origin, static_player_position;
    uintptr_t vt_actor_manager, vt_controlled_actor, vt_character_control, vt_status, vt_physics;
    uintptr_t camera_slot, vt_camera;
    uint32_t camera_block;
};

inline const ReaderProfile* reader_profile() noexcept {
    static constexpr ReaderProfile old{
        Build::v2976, "1.0.0.2976", 0x6D69190, 0x6D56500, 0x6D77858,
        0x55B62C8, 0x5585C40, 0x55B5460, 0x558D868, 0x5D00F88,
        0x6C8CF30, 0x5D20718, 0x428};
    // Static signatures/RTTI plus live pointer, basis, world-position, stat and
    // camera-sentinel checks: tools/porting/data/live_readers_3527.json.
    static constexpr ReaderProfile current{
        Build::v3527, "1.0.0.3527", 0x71BDEF0, 0x71AA150, 0x71CD0B0,
        0x5944B38, 0x59127C8, 0x59438F0, 0x591A710, 0x60CB4D0,
        0x70DA028, 0x60EB0D8, 0x430};
    // Static on the new PE: the same globals through the same code references, the same vtables.
    static constexpr ReaderProfile current3549{
        Build::v3527, "1.0.0.3549", 0x71BDEF0, 0x71AA150, 0x71CD0B0,
        0x5944B38, 0x59127C8, 0x59438F0, 0x591A710, 0x60CB4D0,
        0x70DA028, 0x60EB0D8, 0x430};
    // Build 1.0.0.3576 (static, 2026-11-06; not yet run; docs/research/port-3576.md):
    // - globals by the same AOB patterns as 3527 (tools/porting/data/core_globals_3576.json): world 0x71C0100,
    //   chunk origin 0x71AC2C0 (world_offset_sub 0x397DCB1), static position 0x71CF140, camera slot 0x70DC130;
    // - vtables by RTTI name (vtable_map_3549_3576.json); the camera's by its unique slots 1/2 (0x3BCE5C0, 0x3E33900);
    // - physics 0x60CD660 (no RTTI): the inner's constructor 0x3975E90 allocates 0x270 bytes, calls 0x3C6E430 and stores
    //   the result at inner+0x2C0 (0x3976837); 0x3C6E430 jumps to the protected 0x11214620, which calls its base
    //   constructor and writes vptr 0x60CD660 (0x11214638); slot 1 (0x3C6E6B0 -> 0x11214F30, the deleting destructor)
    //   writes the same vptr (0x11214F41). It is 3527's 0x60CB4D0 + 0x2190, the camera vtable's own move. The chain
    //   control+0x140 -> inner+0x2C0 is read by 39 sites ([[x+0x140]+0x2C0]); 0x397DCCE writes physics+0x90 =
    //   world - chunk origin, 0x3C6E985 reads the basis at physics+0x60;
    // - camera block 0x430: the camera's virtual functions (slots 11, 21, 71) dereference [cam+0x430] as the only large
    //   block, with the SceneConstants fields of docs/research/cheat-tables-versions.md: slot 11 (0x3E36560) writes the
    //   near plane at +0x860 and 0 at +0x864 (the raw "far"), slot 71 (0x3E288C0) uses the screen size and its
    //   reciprocals at +0x30..+0x3C; +0x438 is a small object (+0, +0x60, +0x80). The sentinel (+0xAC0 = 6360000) is
    //   still checked on every read (camera_reader.cpp).
    static constexpr ReaderProfile current3576{
        Build::v3576, "1.0.0.3576", 0x71C0100, 0x71AC2C0, 0x71CF140,
        0x5946C40, 0x5914D58, 0x59459F0, 0x591C7C0, 0x60CD660,
        0x70DC130, 0x60ED268, 0x430};
    // Build 1.0.0.3663 (static, 2026-11-13; never run):
    // - world 0x72451C0 (two AOB patterns); 65 sites read [[[world]+0x30]+0x50] (manager, controlled actor);
    // - chunk origin 0x7231330: world_offset_sub at 0x39F74B1 (`mov rcx,[rbx+0x2D0]; ... vsubps xmm0,[rip->0x7231330];
    //   vmovups [rcx+0x90],xmm0`; 229 references); static position 0x7253E60 (pattern write 0xA616C7, read 0xA615C6);
    // - vtables by RTTI name (vtable_map_3576_3663.json): manager 0x59C2760, actor 0x5990BF0, control 0x59C1660,
    //   status 0x5998B60;
    // - physics 0x614A050 (no RTTI): the inner's constructor allocates 0x270 bytes (0x39EFF8F), calls 0x3CEB620 (jumps to
    //   the protected 0x11B11940, which writes vptr 0x614A050 at 0x11B11958) and stores the result at inner+0x2D0
    //   (0x39F0007); slot 1 0x3CEB8A0 -> 0x11B12170 (deleting destructor) writes the same vptr (0x11B12181).
    //   NOTE: inner+0x2D0, not 3576's +0x2C0: 38 sites read [[x+0x140]+0x2D0], 1 [[x+0x140]+0x2C0] (player_reader.cpp
    //   picks the offset per build). physics+0x60 is passed as the transform (0x3CEBB75 = 3576's 0x3C6E985 + 0x7D1F0);
    // - camera slot 0x71602A8 and vtable 0x6169B58: the camera constructor 0x3EA36D0 (rdi = this, never reassigned)
    //   writes vptr 0x6169B58 (0x3EA3721) and stores rdi at 0x71602A8 (0x3EA4AC3; the only other reference is the
    //   pattern read 0x302CB37); slots 1/2 are the unique patterns 0x3C48340 / 0x3EB1120;
    // - camera block 0x430: slot 11 (0x3EB3D80) writes the near plane at [[cam+0x430]+0x860] and slot 21 (0x3EAB810)
    //   reads +0x430 / +0x438, as in 3576. The stat container offsets are 3527's (not re-derived; reads are bounded).
    static constexpr ReaderProfile current3663{
        Build::v3663, "1.0.0.3663", 0x72451C0, 0x7231330, 0x7253E60,
        0x59C2760, 0x5990BF0, 0x59C1660, 0x5998B60, 0x614A050,
        0x71602A8, 0x6169B58, 0x430};
    switch (current_build()) {
        case Build::v2976: return &old;
        case Build::v3527: return is_3549() ? &current3549 : &current;
        case Build::v3576: return &current3576;
        case Build::v3663: return &current3663;
        default: return nullptr;
    }
}

}  // namespace cdmp::game
