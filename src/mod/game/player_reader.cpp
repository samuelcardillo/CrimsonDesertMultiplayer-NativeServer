#include "mod/game/player_reader.h"

#include <windows.h>

#include <cmath>

#include "common/math3d.h"
#include "mod/game/actor_lookup.h"
#include "mod/game/build_profile.h"
#include "mod/game/offsets.h"
#include "mod/game/safe_memory.h"

namespace cdmp::game {
namespace off = build_2976;

namespace {

std::optional<proto::Vec3> read_vec3(uintptr_t addr) {
    float f[3];
    if (!safe_read(addr, f, sizeof f)) return std::nullopt;
    proto::Vec3 v{f[0], f[1], f[2]};
    if (!math::is_finite(v)) return std::nullopt;
    return v;
}

// Builds 3527 and 3549 (read live on 3549, 2026-11-05): the main character's ClientMercenaryClanActorComponent and the key
// of the character in control, which the game's focus routine 0x23144B0 writes (session2/focus_follow_logic.h).
constexpr uintptr_t kVtMercenaryClan = 0x594D250;
// Build 1.0.0.3576 (static, 2026-11-06; not yet run): the vtable by RTTI name (vtable_map_3549_3576.json); its vf23 is
// 3527's + 0xD50 (0x2315120) and the focus routine (3527 0x23144B0) moved the same way to 0x2315200, which still stores
// the new key with `mov [rdi+0x118],r15d` (0x23154AC). The component slot +0x110 is 3527's (not re-derived: a wrong slot
// fails the vtable check and the main character is read).
constexpr uintptr_t kVtMercenaryClan3576 = 0x594F340;
// Build 1.0.0.3663 (static, 2026-11-13; never run): the vtable by RTTI name (vtable_map_3576_3663.json); its vf23 is
// 0x2385E20 and the focus routine is again vf23 + 0xE0 (0x2385F00, a .pdata start), still storing the new key with
// `mov [rdi+0x118],r15d` at its +0x2AC (0x23861AC), as 3576's at 0x23154AC. The component slot +0x110 is not re-derived.
constexpr uintptr_t kVtMercenaryClan3663 = 0x59CAFB8;
constexpr uint32_t kComponents_Clan = 0x110, kClan_Focus = 0x118;

// The physics object in the control's inner. Build 1.0.0.3663 (static, 2026-11-13; never run): +0x2D0, not +0x2C0: the
// inner's constructor stores it at 0x39F0007 (`mov [rdi+0x2D0],rax`), 38 sites read [[x+0x140]+0x2D0] (1 reads +0x2C0)
// and world_offset_sub (0x39F74B1) takes it from [rbx+0x2D0] (build_profile.h, current3663).
uint32_t inner_physics_offset() {
    return current_build() == Build::v3663 ? 0x2D0 : off::kControlInner_Physics;
}

}  // namespace

bool PlayerReader::init() {
    base_ = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    profile_ = reader_profile();
    enabled_ = profile_ != nullptr;
    if (!enabled_) last_failure_ = "unsupported game build";
    return enabled_;
}

std::nullopt_t PlayerReader::fail(const char* why) {
    last_failure_ = why;
    return std::nullopt;
}

std::optional<uintptr_t> PlayerReader::resolve_actor() {
    auto world = read_ptr(base_ + profile_->world_system);
    if (!world) return fail("WorldSystem not created");
    auto manager = read_ptr(*world + off::kWorldSystem_ActorManager);
    if (!manager || !has_vtable(*manager, base_ + profile_->vt_actor_manager))
        return fail("ClientActorManager missing");
    auto actor = read_ptr(*manager + off::kActorManager_ControlledActor);
    if (!actor) return fail("no controlled actor (not in world)");
    if (!has_vtable(*actor, base_ + profile_->vt_controlled_actor))
        return fail("controlled actor has unexpected type");
    if (follow_focus_ && (layout_3527() || current_build() == Build::v3663)) {
        if (auto focus = focus_actor(*actor)) return focus;
    }
    return actor;
}

// The character in control when it is not the main one; nullopt otherwise (or when anything is unreadable: the main one).
std::optional<uintptr_t> PlayerReader::focus_actor(uintptr_t main_actor) {
    auto components = read_ptr(main_actor + off::kActor_ComponentTable);
    if (!components) return std::nullopt;
    auto clan = read_ptr(*components + kComponents_Clan);
    const uintptr_t vt_clan = current_build() == Build::v3663   ? kVtMercenaryClan3663
                              : current_build() == Build::v3576 ? kVtMercenaryClan3576
                                                                : kVtMercenaryClan;
    if (!clan || !has_vtable(*clan, base_ + vt_clan)) return std::nullopt;
    auto focus = game::read<uint32_t>(*clan + kClan_Focus);
    auto main_key = game::read<uint32_t>(main_actor + off::kActor_Key);
    if (!focus || !main_key || *focus == 0 || *focus == *main_key) return std::nullopt;
    if ((*focus >> 28) != 0xA && (*focus >> 28) != 0xB) return std::nullopt;
    auto actor = find_actor(*focus);
    if (!actor || !*actor || !has_vtable(*actor, base_ + profile_->vt_controlled_actor)) return std::nullopt;
    return actor;
}

std::optional<uintptr_t> PlayerReader::character_control() {
    if (!enabled_) return fail("unsupported game build");
    auto actor = resolve_actor();
    if (!actor) return std::nullopt;
    auto components = read_ptr(*actor + off::kActor_ComponentTable);
    if (!components) return fail("component table missing");
    auto control = read_ptr(*components + off::kComponents_CharacterControl);
    if (!control || !has_vtable(*control, base_ + profile_->vt_character_control))
        return fail("CharacterControl component missing");
    return control;
}

std::optional<PlayerSnapshot> PlayerReader::read() {
    if (!enabled_) return fail("unsupported game build");

    auto actor = resolve_actor();
    if (!actor) return std::nullopt;

    auto components = read_ptr(*actor + off::kActor_ComponentTable);
    if (!components) return fail("component table missing");
    auto control = read_ptr(*components + off::kComponents_CharacterControl);
    if (!control || !has_vtable(*control, base_ + profile_->vt_character_control))
        return fail("CharacterControl component missing");
    auto inner = read_ptr(*control + off::kControl_Inner);
    if (!inner) return fail("control inner missing");
    auto physics = read_ptr(*inner + inner_physics_offset());
    if (!physics || !has_vtable(*physics, base_ + profile_->vt_physics))
        return fail("physics object missing");

    auto local = read_vec3(*physics + off::kPhysics_Position);
    auto origin = read_vec3(base_ + profile_->chunk_origin);
    auto ax = read_vec3(*physics + off::kPhysics_AxisX);
    auto ay = read_vec3(*physics + off::kPhysics_AxisY);
    auto az = read_vec3(*physics + off::kPhysics_AxisZ);
    if (!local || !origin || !ax || !ay || !az) return fail("physics data unreadable");
    if (!math::is_orthonormal(*ax, *ay, *az)) return fail("physics basis not a rotation");

    PlayerSnapshot snap;
    snap.position = math::add(*local, *origin);
    snap.local_position = *local;
    snap.chunk_origin = *origin;
    snap.rotation = math::quat_from_axes(*ax, *ay, *az);

    // The game keeps its own world-space copy; a large mismatch means our
    // chunk-origin math or chain is off (it lags by a frame, so allow some).
    if (auto global = read_vec3(base_ + profile_->static_player_position)) {
        snap.static_pos_error = math::length(math::sub(snap.position, *global));
    }

    // While a save loads, the game parks the actor at (0, 1000, 0) for tens
    // of seconds before placing it. Don't broadcast that as a real position.
    if (std::fabs(snap.position.x) < off::kLoadingParkRadius &&
        std::fabs(snap.position.z) < off::kLoadingParkRadius &&
        std::fabs(snap.position.y - off::kLoadingParkHeight) < off::kLoadingParkRadius) {
        return fail("loading (actor parked at 0,1000,0)");
    }

    read_stats(*components, snap);
    last_failure_.clear();
    return snap;
}

void PlayerReader::read_stats(uintptr_t components, PlayerSnapshot& out) {
    auto status = read_ptr(components + off::kComponents_Status);
    if (!status || !has_vtable(*status, base_ + profile_->vt_status)) return;
    auto container = read_ptr(*status + off::kStatus_StatContainer);
    if (!container) return;
    auto entries = read_ptr(*container + off::kStatContainer_Entries);
    auto count = game::read<uint32_t>(*container + off::kStatContainer_Count);
    if (!entries || !count || *count > off::kMaxStatEntries) return;

    // Look stats up by id: the entry order changes between patches.
    for (uint32_t i = 0; i < *count; ++i) {
        const uintptr_t e = *entries + static_cast<uintptr_t>(i) * off::kStatEntry_Size;
        auto id = game::read<uint64_t>(e + off::kStatEntry_Id);
        if (!id) continue;
        float* cur_out = nullptr;
        float* max_out = nullptr;
        if (*id == off::kStatId_Health) {
            cur_out = &out.health;
            max_out = &out.health_max;
        } else if (*id == off::kStatId_Stamina) {
            cur_out = &out.stamina;
            max_out = &out.stamina_max;
        } else {
            continue;
        }
        auto cur = game::read<int64_t>(e + off::kStatEntry_Current);
        auto max = game::read<int64_t>(e + off::kStatEntry_Max);
        if (!cur || !max || *max <= 0 || *cur < 0 || *cur > *max) continue;
        *cur_out = static_cast<float>(*cur) / 1000.0f;
        *max_out = static_cast<float>(*max) / 1000.0f;
    }
}

}  // namespace cdmp::game
