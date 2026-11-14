#include "mod/session2/vehicle_follow.h"

#include <windows.h>

#include <safetyhook.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstring>
#include <format>
#include <span>
#include <string>
#include <vector>

#include "common/movement_layout.h"
#include "mod/game/build_profile.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"
#include "mod/session2/gimmick_interact_logic.h"
#include "mod/session2/p8_probes.h"
#include "mod/session2/vehicle_follow_logic.h"

namespace cdmp::session2 {
namespace {

// The build's addresses: the two TransformSync request setters (TS*, const Pos* / const Quat*, u8 type, ...), the world
// slot, pa::ClientChildOnlyInGameActor's vtable, and the field-change controller's load state ([world+0x60]+state_off,
// in_world_state once a load has ended).
// The pending request's type at TS+0x5BC when there is none; also "no such type known" in Addrs.
constexpr uint8_t kRequestNone = 0xF;
struct Addrs {
    uintptr_t set_position, set_rotation, world_slot, vt_child_only;
    uint32_t state_off;
    uint8_t in_world_state;
    uint8_t request_type;      // the per-frame request of a vehicle drawn from its gimmick, this client NEAR it
    uint8_t request_type_far;  // the low-rate one while this client is far from it (kRequestNone: not known)
    // The request a character's movement gives its own TransformSync every frame (passengers below; kRequestNone:
    // not looked at for the build, no passenger is ever placed).
    uint8_t char_request_type;
    // The parts' scene objects (parts_pass below): the scene object's vtable and the actor component (comps+0x30) that
    // points into it. 0: not derived for the build (no part is ever touched).
    uintptr_t vt_scene_object, vt_scene_comp;
};
// Build 1.0.0.3576 (capstone on the installed PE and hardware write watches on the guest copy, 2026-11-13; see
// vehicle_follow.h and docs/ESTADO-3527.md "13-nov: BARCO").
constexpr Addrs kAddrs3576{0xB03BB0, 0xB03FB0, 0x71C0100, 0x5914D58, 0x15C, 0x18, 7, kRequestNone, kRequestNone, 0, 0};
// Build 1.0.0.3663 (static, 2026-11-13; never run; docs/research/port-3663.md): both setters found by their whole
// entry bytes below (the position one is unique; the rotation one also matches 0x24A3A50, another function, and is
// the one 0x400 after the position setter as in 3576), and the position setter still stores the request as in 3576
// (pose at TS+0x5AC, type at +0x5BC, flags +0x5BD/+0x5BE: 0xB39EE7..0xB39F19); world slot by two AOB patterns
// (core_globals.py); the vtable by RTTI name (vtable_map_3576_3663.json). Checked in 3663's code: comps+0x1A0 is still
// the TransformSync (all 24 callers of the position setter load rcx = [x+0x1A0], e.g. 0x7A47B8, 0x8847FD) and the network
// pose is still used as before (0xB35084 / 0xB358C1 subtract [ts+0x550] from the current position, with ts+0x55C taken
// next to it; 0xB42A0D writes +0x550). The other object offsets below (actor table, components +0x48/+0x1B8, hierarchy
// +0x18/+0x1C) are 3576's, not re-derived (a wrong one only means no vehicle is found). The load controller grew by
// 0xF0 and gained a state (port group 1, guest.cpp: the loading state machine 0x8825B0 and five sites reading
// [[world]+0x60]+0x24C with dec al; cmp al,0x17): state at +0x24C, in the world at 0x19.
// Request types on 3663 (live, two copies, 2026-11-13 and 14): with this client NEAR the ship its vehicle gets a type-7
// request every frame, as on 3576 (14-nov 02:57, guest standing on the host's ship: {15: 303865, 7: 1842} in 2 s of
// polling TS+0x5BC); with this client FAR from it (13-nov 21:58 and 14-nov 02:23, guest at its join point 6 km away)
// it gets type 12 a few times a second (1029 in the first two minutes, none after the guest's fast travel to the
// quay), and the pose of that request already is the network one (error 0.0-0.1 m). With only 12 (the first 3663
// table, 13-nov night) nothing was followed near the ship: the guest's copy stayed at the mooring while the host
// sailed 180 m away (14-nov 02:55). The setter stores the type it is given (0xB39F01).
// Scene objects (14-nov, hardware write watch on the wheel's TS on both copies): the TransformSync tick 0xB3A3B0 (TS
// vf59) is called by the scene object's transform notification (0x39645A0 from 0x3964D30) with the scene object in
// rdx; the object's world transform comes from 0x29657F0 (parent's, through the link at +0x80, composed with the local
// one at +0x1D0); [[comps+0x30]+0x18]-0x28 is that object for all 24 parts of the ship on both copies (scene object
// vtable 0x5989550, the component's 0x59C3768).
// Characters (14-nov 03:55, both copies, 3 s of polling TS+0x5BC): the other player's character and this client's own
// get type-12 requests every frame ({15: 445412, 12: 1432} on the host for the guest's, {12: 3562} on the guest for the
// host's); the same number as the far vehicle's, on another TransformSync.
constexpr Addrs kAddrs3663{0xB39E40, 0xB3A240, 0x72451C0, 0x5990BF0, 0x24C, 0x19, 7, 12, 12, 0x5989550, 0x59C3768};
const Addrs* g_addrs = nullptr;
// Both entries start with the same three register saves; the bytes after them tell the two apart.
constexpr uint8_t kSetPositionHead[24] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89,
                                          0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x0F, 0xBF, 0x42, 0x0E};
constexpr uint8_t kSetRotationHead[23] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89,
                                          0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x70, 0x48, 0x8B, 0xD9};
constexpr uint32_t kPatch = 5;  // the first register save, a whole instruction (safetyhook patches 5 bytes)

constexpr uint32_t kWorld_Mgr = 0x30, kMgr_Table = 0x08, kMgr_OwnActor = 0x50, kMgr_User = 0x58, kUser_Key = 0x60;
constexpr uint32_t kTable_Buckets = 0x98, kTable_Nodes = 0xA0, kTable_Count = 0x88, kBucketStride = 0x100;
constexpr uint32_t kActor_Comps = 0x68, kActor_Info = 0x88, kActor_Controller = 0x90, kActor_Key = 0x60;
constexpr uint32_t kComps_Vehicle = 0x48, kComps_Hierarchy = 0x1B8, kComps_TS = 0x1A0;
constexpr uint32_t kHier_AttachType = 0x18, kHier_Parent = 0x1C;
constexpr uint32_t kTS_Actor = 0x08, kTS_NetPos = 0x550, kTS_NetQuat = 0x55C;
// The pending request's type (0xF = none), from the setter until the TransformSync tick consumes it (same frame).
constexpr uint32_t kTS_RequestType = 0x5BC;
constexpr uint32_t kTS_LocalQuat = 0xA4, kTS_LocalPos = 0xB4, kTS_LocalSector = 0xC0;
constexpr uint8_t kTypeGimmick = 7, kTypeVehicle = 5, kAttachVehicle = 7;
// Every vehicle actor of the other user with a vehicle gimmick hanging from it is listed, not only the one with a ship
// out: the host's stabled horses carry ten-odd each (13-nov, both copies: 0xB0100004/5/7, 9-12 gimmicks) and never get
// a vehicle request (type 7; on 3663 also 12 from far away). One entry per vehicle actor.
constexpr size_t kMaxVehicles = 16;
constexpr ULONGLONG kProbeMs = 100;  // ~6 frames at 60 fps

struct Vehicle {
    std::atomic<uintptr_t> ts{0};
    std::atomic<uint32_t> key{0};
    uint32_t gimmick = 0, gimmicks = 0;  // one of the vehicle gimmicks hanging from it and their number (log only)
    bool following = false;              // worker only: a vehicle request seen (it is drawn from its gimmick)
    SRWLOCK lock = SRWLOCK_INIT;
    vfl::Track track;        // under lock
    vfl::Pose drawn;         // under lock: the pose given to the last position request
    uint64_t drawn_ms = 0;   // under lock
    std::atomic<uint64_t> requests{0}, positions{0}, rotations{0}, samples{0};
    std::atomic<uint32_t> last_err_cm{0}, max_err_cm{0};
};
std::array<Vehicle, kMaxVehicles> g_vehicles;

uintptr_t g_base = 0;
std::atomic<bool> g_started{false};
std::atomic<uint8_t> g_mode{0};
std::atomic<bool> g_guest{false};
SafetyHookMid g_pos_hook, g_rot_hook;
std::atomic<uint64_t> g_unreadable{0};
std::atomic<uint32_t> g_delay_ms{static_cast<uint32_t>(vfl::Track::kDefaultDelayMs)};

// SEH-guarded reads without VirtualQuery (game::fast_read): the scan reads thousands of heap fields, and a
// VirtualQuery per read contends with the game's own allocations (it is also never run during a load: in_world()).
template <class T>
T rd(uintptr_t a, T fallback = T{}) noexcept {
    T v{};
    return a > 0x10000 && game::fast_read(a, &v, sizeof v) ? v : fallback;
}
bool write_bytes(uintptr_t a, const void* src, size_t n) noexcept {
    if (a < 0x10000) return false;
    __try {
        std::memcpy(reinterpret_cast<void*>(a), src, n);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
bool on() noexcept { return static_cast<gil::Mode>(g_mode.load(std::memory_order_relaxed)) == gil::Mode::On; }
// A request of a vehicle drawn from its gimmick (near or far).
bool vehicle_request(uint8_t type) noexcept {
    return type == g_addrs->request_type || (g_addrs->request_type_far != kRequestNone && type == g_addrs->request_type_far);
}

// The client is in the world, not loading: the field-change controller's state is the build's last one (3576: every
// load passes 0x4..0x17 and ends at 0x18 at [[world+0x60]+0x15C], guest.cpp's 'Session2 guest load' lines).
constexpr uint32_t kWorld_FieldChange = 0x60;
bool in_world() noexcept {
    const uintptr_t world = rd<uintptr_t>(g_base + g_addrs->world_slot);
    const uintptr_t fc = world ? rd<uintptr_t>(world + kWorld_FieldChange) : 0;
    return fc && rd<uint8_t>(fc + g_addrs->state_off) == g_addrs->in_world_state;
}

Vehicle* find(uintptr_t ts) noexcept {
    if (!ts) return nullptr;
    for (auto& v : g_vehicles)
        if (v.ts.load(std::memory_order_acquire) == ts) return &v;
    return nullptr;
}

// ---------------------------------------------------------------- passengers
// The other player's character standing on a ship part (2026-11-14, 3663, two copies, host at the wheel and guest on the
// bow deck). The client draws another player's character at the WORLD pose of its Moves (its parent's world transform
// as the sender had it, composed with the local pose); it is never attached to this client's copy of the parent. So:
//  - a passenger that stands still sends no Move, and stays where its last one left it: the host saw the guest 13 m
//    astern at 4.8 m/s and 107 m astern at 12.7 m/s, in the water, until the guest's next Move;
//  - the helmsman on the guest sits 0.3-1.9 m (4 m at a sudden stop) from the wheel: its samples and the ship's are
//    drawn with different delays.
// Here: when the other player's last Move names a gimmick (type 7) that hangs from a vehicle actor (type 5), its
// character's own per-frame position and rotation requests (type 12 on 3663) get the pose of THIS client's copy of that
// gimmick (its TransformSync local poses composed up to the vehicle) composed with the Move's local pose, eased over
// kPassengerEaseMs. On foot, or on a horse (a type-5 parent), nothing is touched. Both PCs; needs the build's character
// request type (3663). probe: measured, not written.
// A passenger standing still gets few requests of its own (the helmsman on the guest: ~2 a second, 14-nov 04:35: 0.4-0.6
// m off the wheel at 3.4 m/s, 2-3 m at 13 m/s). So, with 1, every time THIS client's own character gets its per-frame
// request (the same kind, in the same part of the frame), each passenger whose own request is more than
// kPassengerIdleMs old is given one through the game's own setters, called as its movement calls them (0xB39E40:
// TS*, pos*, type, has-velocity 0, velocity null, the two flag bytes of its last own request; 0xB3A240: TS*, quat*,
// type, flag): they store the request (TS+0x5AC.. / +0x5C0..) and set bit 0 of the actor's byte +0x100 (its vf54),
// nothing else. The TransformSync is checked against its actor and key right before, and the call is SEH-guarded.
constexpr size_t kMaxPassengers = 4, kMaxChain = 4;
constexpr ULONGLONG kPassengerEaseMs = 120, kPassengerIdleMs = 30, kChannelFreshMs = 2000;
constexpr float kPassengerSnapM = 3.0f;
using SetPositionFn = void (*)(uintptr_t ts, const void* pos, uint8_t type, uint8_t has_velocity, const void* velocity,
                               uint8_t flag_a, uint8_t flag_b);
using SetRotationFn = void (*)(uintptr_t ts, const float* quat, uint8_t type, uint8_t flag);
thread_local bool t_own_call = false;  // inside one of this module's own setter calls: the hooks pass it through
std::atomic<uintptr_t> g_own_ts{0};    // this client's own character's TransformSync (worker)

struct Passenger {
    std::atomic<uint32_t> key{0};   // the other player's character; 0: free (worker)
    std::atomic<uintptr_t> ts{0};   // its TransformSync here (worker; the hooks compare pointers)
    SRWLOCK lock = SRWLOCK_INIT;
    // Its controller's last Move: the mod's network thread writes, the hooks read (under lock).
    uint32_t parent = 0;            // 0: no parent (on foot)
    float pos[3]{}, q[4]{0, 0, 0, 1};
    // The parent's TransformSyncs on this client, from the parent up to the root vehicle (worker writes: chain_for = 0,
    // the chain, then chain_for = the parent key they belong to).
    std::atomic<uint32_t> chain_for{0}, chain_len{0}, vehicle{0};
    std::array<std::atomic<uintptr_t>, kMaxChain> chain{};
    // Hook side, under lock: the eased local pose and the world rotation of the last position request.
    float eased_pos[3]{}, eased_q[4]{0, 0, 0, 1}, drawn_q[4]{0, 0, 0, 1};
    ULONGLONG eased_ms = 0, drawn_ms = 0;
    uint32_t eased_for = 0;
    std::atomic<uint64_t> moves{0}, requests{0}, placed{0}, unreadable{0}, idle_placed{0}, idle_failed{0};
    std::atomic<uint32_t> last_off_cm{0}, max_off_cm{0};
    // Its own last request: when, and the arguments this module's calls copy (hooks).
    std::atomic<ULONGLONG> request_ms{0};
    // The last state of it from the mod's own channel (vehicle_follow_on_peer_state): while those arrive, the game's
    // Moves of it are not used (the server blanks them for a character on a ship's deck).
    std::atomic<ULONGLONG> channel_ms{0};
    std::atomic<uint64_t> channel_states{0};
    std::atomic<uint8_t> flag_a{0}, flag_b{0}, rot_type{kRequestNone}, rot_flag{0};
    std::atomic<bool> busy{false};
    uint32_t logged_parent = 0;     // worker only
};
std::array<Passenger, kMaxPassengers> g_passengers;
std::atomic<uint32_t> g_passenger_count{0};

Passenger* find_passenger(uintptr_t ts) noexcept {
    if (!ts || !g_passenger_count.load(std::memory_order_relaxed)) return nullptr;
    for (auto& p : g_passengers)
        if (p.ts.load(std::memory_order_acquire) == ts) return &p;
    return nullptr;
}

// A TransformSync's local pose (world for a root: the sector added).
bool ts_pose(uintptr_t ts, bool root, vfl::Pose* out, float local_pos[3]) noexcept {
    float pos[3], q[4];
    int16_t sector[2];
    if (!game::fast_read(ts + kTS_LocalPos, pos, sizeof pos) || !game::fast_read(ts + kTS_LocalQuat, q, sizeof q) ||
        !game::fast_read(ts + kTS_LocalSector, sector, sizeof sector))
        return false;
    if (!vfl::unit_quat(q) || !std::isfinite(pos[0]) || !std::isfinite(pos[1]) || !std::isfinite(pos[2])) return false;
    if (root) {
        out->x = pos[0] + sector[0] * 1000.0;
        out->y = pos[1];
        out->z = pos[2] + sector[1] * 1000.0;
    } else {
        if (sector[0] || sector[1]) return false;
        std::memcpy(local_pos, pos, sizeof pos);
    }
    std::memcpy(out->q, q, sizeof q);
    return true;
}

// The world pose of the passenger's parent on this client: the chain's poses composed from the root down.
bool chain_world(const Passenger& p, vfl::Pose* out) noexcept {
    const uint32_t n = p.chain_len.load(std::memory_order_acquire);
    if (!n || n > kMaxChain) return false;
    vfl::Pose w;
    float unused[3];
    if (!ts_pose(p.chain[n - 1].load(std::memory_order_relaxed), true, &w, unused)) return false;
    for (uint32_t i = n - 1; i-- > 0;) {
        vfl::Pose l;
        float lp[3];
        if (!ts_pose(p.chain[i].load(std::memory_order_relaxed), false, &l, lp)) return false;
        w = vfl::attach(w, lp, l.q);
    }
    *out = w;
    return vfl::finite_pose(w);
}

// The passenger's world pose now (its eased local pose on this client's copy of its parent). False: not on a ship
// part, or its parent's poses are unreadable.
bool passenger_pose(Passenger& p, ULONGLONG now, vfl::Pose* out_pose) noexcept {
    float lp[3], lq[4];
    uint32_t parent = 0;
    AcquireSRWLockExclusive(&p.lock);
    parent = p.parent;
    if (parent && p.chain_for.load(std::memory_order_acquire) == parent) {
        float d[3] = {p.pos[0] - p.eased_pos[0], p.pos[1] - p.eased_pos[1], p.pos[2] - p.eased_pos[2]};
        const float gap = std::sqrt(d[0] * d[0] + d[1] * d[1] + d[2] * d[2]);
        const ULONGLONG dt = now - p.eased_ms;
        if (p.eased_for != parent || gap > kPassengerSnapM || dt > 1000) {
            std::memcpy(p.eased_pos, p.pos, sizeof p.pos);
            std::memcpy(p.eased_q, p.q, sizeof p.q);
        } else {
            const double a = std::min(1.0, static_cast<double>(dt) / kPassengerEaseMs);
            for (int i = 0; i < 3; ++i) p.eased_pos[i] += static_cast<float>(d[i] * a);
            float q[4];
            vfl::nlerp(p.eased_q, p.q, a, q);
            std::memcpy(p.eased_q, q, sizeof q);
        }
        p.eased_for = parent;
        p.eased_ms = now;
        std::memcpy(lp, p.eased_pos, sizeof lp);
        std::memcpy(lq, p.eased_q, sizeof lq);
    } else {
        parent = 0;
        p.eased_for = 0;
        p.drawn_ms = 0;
    }
    ReleaseSRWLockExclusive(&p.lock);
    if (!parent) return false;
    vfl::Pose base;
    if (!chain_world(p, &base)) {
        p.unreadable.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    const vfl::Pose out = vfl::attach(base, lp, lq);
    if (!vfl::finite_pose(out) || !vfl::unit_quat(out.q)) return false;
    *out_pose = out;
    return true;
}

struct PositionArg {
    float x, y, z;
    int16_t sx, sz;
};

void passenger_position(safetyhook::Context& ctx, Passenger& p) noexcept {
    const ULONGLONG now = GetTickCount64();
    p.request_ms.store(now, std::memory_order_relaxed);
    p.flag_a.store(rd<uint8_t>(ctx.rsp + 0x30), std::memory_order_relaxed);
    p.flag_b.store(rd<uint8_t>(ctx.rsp + 0x38), std::memory_order_relaxed);
    vfl::Pose out;
    if (!passenger_pose(p, now, &out)) return;
    p.requests.fetch_add(1, std::memory_order_relaxed);
    PositionArg arg{};
    if (!game::fast_read(ctx.rdx, &arg, sizeof arg)) return;
    const double ox = arg.x + arg.sx * 1000.0 - out.x, oy = arg.y - out.y, oz = arg.z + arg.sz * 1000.0 - out.z;
    const auto off_cm = static_cast<uint32_t>(std::min(std::sqrt(ox * ox + oy * oy + oz * oz) * 100.0, 4.0e9));
    p.last_off_cm.store(off_cm, std::memory_order_relaxed);
    if (off_cm > p.max_off_cm.load(std::memory_order_relaxed)) p.max_off_cm.store(off_cm, std::memory_order_relaxed);
    AcquireSRWLockExclusive(&p.lock);
    std::memcpy(p.drawn_q, out.q, sizeof out.q);
    p.drawn_ms = now;
    ReleaseSRWLockExclusive(&p.lock);
    if (!on()) return;
    PositionArg w{};
    vfl::to_sector(out.x, arg.sx, &w.x, &w.sx);
    vfl::to_sector(out.z, arg.sz, &w.z, &w.sz);
    w.y = static_cast<float>(out.y);
    if (write_bytes(ctx.rdx, &w, sizeof w)) p.placed.fetch_add(1, std::memory_order_relaxed);
}

// The two setters called for a TransformSync (no C++ objects here: SEH).
bool call_setters(uintptr_t ts, const PositionArg* pos, const float* quat, uint8_t type, uint8_t flag_a, uint8_t flag_b,
                  uint8_t rot_type, uint8_t rot_flag) noexcept {
    const auto set_position = reinterpret_cast<SetPositionFn>(g_base + g_addrs->set_position);
    const auto set_rotation = reinterpret_cast<SetRotationFn>(g_base + g_addrs->set_rotation);
    bool ok = true;
    t_own_call = true;
    __try {
        set_position(ts, pos, type, 0, nullptr, flag_a, flag_b);
        if (rot_type != kRequestNone) set_rotation(ts, quat, rot_type, rot_flag);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    t_own_call = false;
    return ok;
}

// From this client's own character's request (once a frame): the passengers that got no request of their own lately.
void passengers_idle(ULONGLONG now) noexcept {
    if (!on()) return;
    for (auto& p : g_passengers) {
        const uintptr_t ts = p.ts.load(std::memory_order_acquire);
        if (!ts || !p.chain_for.load(std::memory_order_relaxed)) continue;
        if (now - p.request_ms.load(std::memory_order_relaxed) < kPassengerIdleMs) continue;
        if (p.busy.exchange(true, std::memory_order_acquire)) continue;
        vfl::Pose out;
        // Still that character's TransformSync: its actor, the actor's key, and the actor's components point back.
        const uintptr_t actor = rd<uintptr_t>(ts + kTS_Actor);
        const uintptr_t comps = actor ? rd<uintptr_t>(actor + kActor_Comps) : 0;
        const bool same = comps && rd<uint32_t>(actor + kActor_Key) == p.key.load(std::memory_order_relaxed) &&
                          rd<uintptr_t>(comps + kComps_TS) == ts;
        if (same && passenger_pose(p, now, &out)) {
            int16_t sector[2]{};
            game::fast_read(ts + kTS_LocalSector, sector, sizeof sector);
            PositionArg w{};
            vfl::to_sector(out.x, sector[0], &w.x, &w.sx);
            vfl::to_sector(out.z, sector[1], &w.z, &w.sz);
            w.y = static_cast<float>(out.y);
            AcquireSRWLockExclusive(&p.lock);
            std::memcpy(p.drawn_q, out.q, sizeof out.q);
            p.drawn_ms = now;
            ReleaseSRWLockExclusive(&p.lock);
            if (call_setters(ts, &w, out.q, g_addrs->char_request_type, p.flag_a.load(std::memory_order_relaxed),
                             p.flag_b.load(std::memory_order_relaxed), p.rot_type.load(std::memory_order_relaxed),
                             p.rot_flag.load(std::memory_order_relaxed))) {
                p.idle_placed.fetch_add(1, std::memory_order_relaxed);
                p.request_ms.store(now, std::memory_order_relaxed);
            } else {
                // A fault inside the game's setter: this character is left alone from now on.
                p.idle_failed.fetch_add(1, std::memory_order_relaxed);
                p.chain_for.store(0, std::memory_order_release);
                p.ts.store(0, std::memory_order_release);
            }
        }
        p.busy.store(false, std::memory_order_release);
    }
}

void passenger_rotation(safetyhook::Context& ctx, Passenger& p) noexcept {
    p.rot_type.store(static_cast<uint8_t>(ctx.r8), std::memory_order_relaxed);
    p.rot_flag.store(static_cast<uint8_t>(ctx.r9), std::memory_order_relaxed);
    float q[4];
    bool have = false;
    AcquireSRWLockShared(&p.lock);
    if (p.drawn_ms && GetTickCount64() - p.drawn_ms < 500) {
        std::memcpy(q, p.drawn_q, sizeof q);
        have = vfl::unit_quat(q);
    }
    ReleaseSRWLockShared(&p.lock);
    if (have) write_bytes(ctx.rdx, q, sizeof q);
}

// The vehicle's network pose (the controller's last sample).
bool network_pose(uintptr_t ts, vfl::Pose* p) noexcept {
    float pos[3], q[4];
    if (!game::fast_read(ts + kTS_NetPos, pos, sizeof pos) || !game::fast_read(ts + kTS_NetQuat, q, sizeof q)) return false;
    p->x = pos[0];
    p->y = pos[1];
    p->z = pos[2];
    std::memcpy(p->q, q, sizeof q);
    return vfl::usable(*p);
}

// Position request: TS in rcx, the pose {f32 x, y, z; i16 sector x, z} at rdx, the type in r8b.
void position_mid(safetyhook::Context& ctx) {
    if (t_own_call) return;
    const auto type = static_cast<uint8_t>(ctx.r8);
    if (type == g_addrs->char_request_type && type != kRequestNone) {
        if (Passenger* p = find_passenger(ctx.rcx)) {
            passenger_position(ctx, *p);
            return;
        }
        if (ctx.rcx == g_own_ts.load(std::memory_order_relaxed) && g_passenger_count.load(std::memory_order_relaxed)) {
            passengers_idle(GetTickCount64());
            return;
        }
    }
    if (!vehicle_request(type)) return;
    Vehicle* v = find(ctx.rcx);
    if (!v) return;
    v->requests.fetch_add(1, std::memory_order_relaxed);
    const uintptr_t actor = rd<uintptr_t>(ctx.rcx + kTS_Actor);
    if (!actor || rd<uint32_t>(actor + kActor_Key) != v->key.load(std::memory_order_relaxed)) return;
    vfl::Pose net;
    if (!network_pose(ctx.rcx, &net)) {
        g_unreadable.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    struct Arg {
        float x, y, z;
        int16_t sx, sz;
    } arg{};
    if (!game::fast_read(ctx.rdx, &arg, sizeof arg)) return;
    const uint64_t now = GetTickCount64();
    vfl::Pose out;
    bool have = false;
    AcquireSRWLockExclusive(&v->lock);
    if (v->track.push(now, net)) v->samples.fetch_add(1, std::memory_order_relaxed);
    have = v->track.at(now, &out);
    if (have) {
        v->drawn = out;
        v->drawn_ms = now;
    }
    ReleaseSRWLockExclusive(&v->lock);
    if (!have) return;
    vfl::Pose local;
    local.x = arg.x + arg.sx * 1000.0;
    local.z = arg.z + arg.sz * 1000.0;
    const auto err_cm = static_cast<uint32_t>(std::min(vfl::dist_xz(local, out) * 100.0, 4.0e9));
    v->last_err_cm.store(err_cm, std::memory_order_relaxed);
    if (err_cm > v->max_err_cm.load(std::memory_order_relaxed)) v->max_err_cm.store(err_cm, std::memory_order_relaxed);
    if (!on()) return;
    Arg w{};
    vfl::to_sector(out.x, arg.sx, &w.x, &w.sx);
    vfl::to_sector(out.z, arg.sz, &w.z, &w.sz);
    w.y = static_cast<float>(out.y);
    if (write_bytes(ctx.rdx, &w, sizeof w)) v->positions.fetch_add(1, std::memory_order_relaxed);
}

// Rotation request: TS in rcx, the quaternion at rdx, the type in r8b. Uses the pose of the position request that
// came just before it (the same update).
void rotation_mid(safetyhook::Context& ctx) {
    if (t_own_call || !on()) return;
    const auto type = static_cast<uint8_t>(ctx.r8);
    // A character's rotation request: whatever type its movement gives it (kept for this module's own calls).
    if (Passenger* p = find_passenger(ctx.rcx)) {
        passenger_rotation(ctx, *p);
        return;
    }
    if (!vehicle_request(type)) return;
    Vehicle* v = find(ctx.rcx);
    if (!v) return;
    float q[4];
    bool have = false;
    AcquireSRWLockShared(&v->lock);
    if (v->drawn_ms && GetTickCount64() - v->drawn_ms < 500) {
        std::memcpy(q, v->drawn.q, sizeof q);
        have = vfl::unit_quat(q);
    }
    ReleaseSRWLockShared(&v->lock);
    if (have && write_bytes(ctx.rdx, q, sizeof q)) v->rotations.fetch_add(1, std::memory_order_relaxed);
}

struct Found {
    uint32_t vehicle, gimmick, gimmicks;
    uintptr_t ts;
};

uintptr_t actor_by_key(uintptr_t table, uint32_t key) noexcept {
    const uint32_t n = rd<uint32_t>(table + kTable_Count);
    const uintptr_t buckets = rd<uintptr_t>(table + kTable_Buckets), nodes = rd<uintptr_t>(table + kTable_Nodes);
    if (!n || n > (1u << 24) || !buckets || !nodes) return 0;
    const uintptr_t b = buckets + static_cast<uintptr_t>(key % n) * kBucketStride;
    const uint32_t c = rd<uint32_t>(b);
    for (uint32_t i = 0; i < c && i < 31; ++i) {
        if (rd<uint32_t>(b + 8 + i * 8) != key) continue;
        const uint32_t idx = rd<uint32_t>(b + 0xC + i * 8);
        const uintptr_t node = rd<uintptr_t>(nodes + static_cast<uintptr_t>(idx) * 8);
        return node ? rd<uintptr_t>(node + 8) : 0;
    }
    return 0;
}

// The vehicle actors another user controls that a vehicle gimmick hangs from: every type-7 actor with a vehicle
// component hanging (attach type 7) from a type-5 ChildOnly actor whose controller is not this client's user. One entry
// per vehicle actor (most are stabled horses with their gear; the one with a ship out is told apart by its requests).
std::vector<Found> scan(uint32_t* own_out, uint32_t* dropped_out) {
    std::vector<Found> out;
    const uintptr_t world = rd<uintptr_t>(g_base + g_addrs->world_slot);
    const uintptr_t mgr = world ? rd<uintptr_t>(world + kWorld_Mgr) : 0;
    const uintptr_t table = mgr ? rd<uintptr_t>(mgr + kMgr_Table) : 0;
    const uintptr_t user = mgr ? rd<uintptr_t>(mgr + kMgr_User) : 0;
    const uint32_t own = user ? rd<uint32_t>(user + kUser_Key) : 0;
    *own_out = own;
    *dropped_out = 0;
    if (!table || !own) return out;
    const uint32_t n = rd<uint32_t>(table + kTable_Count);
    const uintptr_t buckets = rd<uintptr_t>(table + kTable_Buckets), nodes = rd<uintptr_t>(table + kTable_Nodes);
    if (!n || n > (1u << 20) || !buckets || !nodes) return out;
    for (uint32_t b = 0; b < n; ++b) {
        const uintptr_t base = buckets + static_cast<uintptr_t>(b) * kBucketStride;
        const uint32_t c = rd<uint32_t>(base);
        for (uint32_t i = 0; i < c && i < 31; ++i) {
            const uint32_t idx = rd<uint32_t>(base + 0xC + i * 8);
            const uintptr_t node = rd<uintptr_t>(nodes + static_cast<uintptr_t>(idx) * 8);
            const uintptr_t a = node ? rd<uintptr_t>(node + 8) : 0;
            const uintptr_t info = a ? rd<uintptr_t>(a + kActor_Info) : 0;
            if (!info || rd<uint8_t>(info + 1) != kTypeGimmick) continue;
            const uintptr_t comps = rd<uintptr_t>(a + kActor_Comps);
            const uintptr_t hier = comps && rd<uintptr_t>(comps + kComps_Vehicle) ? rd<uintptr_t>(comps + kComps_Hierarchy) : 0;
            if (!hier || rd<uint8_t>(hier + kHier_AttachType) != kAttachVehicle) continue;
            const uint32_t parent_key = rd<uint32_t>(hier + kHier_Parent);
            const auto listed = std::find_if(out.begin(), out.end(), [&](const Found& f) { return f.vehicle == parent_key; });
            if (listed != out.end()) {
                ++listed->gimmicks;
                continue;
            }
            const uintptr_t p = parent_key ? actor_by_key(table, parent_key) : 0;
            const uintptr_t pinfo = p ? rd<uintptr_t>(p + kActor_Info) : 0;
            if (!pinfo || rd<uintptr_t>(p) != g_base + g_addrs->vt_child_only || rd<uint8_t>(pinfo + 1) != kTypeVehicle) continue;
            const uint32_t ctl = rd<uint32_t>(p + kActor_Controller);
            if (!ctl || ctl == own) continue;
            const uintptr_t pcomps = rd<uintptr_t>(p + kActor_Comps);
            const uintptr_t ts = pcomps ? rd<uintptr_t>(pcomps + kComps_TS) : 0;
            if (!ts || rd<uintptr_t>(ts + kTS_Actor) != p) continue;
            if (out.size() == kMaxVehicles) {
                ++*dropped_out;
                continue;
            }
            out.push_back({parent_key, rd<uint32_t>(a + kActor_Key), 1, ts});
        }
    }
    return out;
}

// ---------------------------------------------------------------- the parts of a followed ship
// The ship's wheel on the other player's client (2026-11-14, 3663, two copies; the user's report "the ship wheel is
// flying"): the wheel gimmick hangs from its mount's socket (hierarchy attach type 6; the mount hangs from the vehicle
// at (0, 2.94, 1.85)). On the controller's client its scene object's local transform is (0, 0.81, 0.29); on the other
// client the same object is created with (0, 3.76, 2.14), its offset from the VEHICLE, so it is drawn 2.9 m above the
// deck and 1.9 m astern. Nothing rewrites it afterwards (30 s of write watch on both copies: no write), and the
// TransformSync only copies it (a write to the TS is undone within a tick; one write to the scene object's local
// position stays, and the TS, the world pose and the picture follow). The controller's local pose of the part arrives
// about once a second in its MoveActorAck, which the client never applies to a gimmick.
// So: for every gimmick attached by a socket (attach 6) under a followed vehicle, when its scene object's local position
// is more than kPartOffM (0.5 m; a rope ladder hangs 0.33 m apart on the two copies) from the controller's last one
// (same parent), the position is written once into the scene
// object. At most kMaxPartFixes times per part (something else would be moving it). Only where the build's scene
// object is known (3663). probe: logged, not written.
constexpr uint16_t kOpMoveActorAck = 2697, kOpMoveActorReq = 2556;  // logical opcodes
constexpr uint32_t kComps_SceneComp = 0x30, kSceneComp_Node = 0x18, kNode_ToObject = 0x28;
constexpr uint32_t kScene_Link = 0x80, kScene_Local = 0x1D0, kXform_Pos = 0x1C, kXform_Sector = 0x28;
constexpr uint8_t kAttachSocket = 6;
constexpr size_t kMaxParts = 48;
constexpr uint32_t kMaxPartFixes = 5;
constexpr float kPartOffM = 0.5f, kPartSettledM = 0.05f;
constexpr ULONGLONG kPartPoseMaxAgeMs = 60000;

struct Part {
    std::atomic<uint32_t> key{0};  // 0: free. Written by the worker; read by the network thread
    // worker only
    uint32_t parent = 0, vehicle = 0, fixes = 0;
    bool seen = false, gave_up = false, probe_logged = false;
    // the controller's last local position of it: under g_parts_lock (network thread writes, worker reads)
    uint32_t net_parent = 0;
    float net_pos[3]{};
    ULONGLONG net_ms = 0;
};
std::array<Part, kMaxParts> g_parts;
SRWLOCK g_parts_lock = SRWLOCK_INIT;
std::atomic<uint32_t> g_part_count{0};
std::atomic<uint64_t> g_part_acks{0}, g_part_fixes{0};

float dist3(const float* a, const float* b) noexcept {
    const float x = a[0] - b[0], y = a[1] - b[1], z = a[2] - b[2];
    return std::sqrt(x * x + y * y + z * z);
}

// The scene object of an actor's components, or 0 (not the build's classes, or not attached to a parent node).
uintptr_t scene_object(uintptr_t comps) noexcept {
    const uintptr_t comp = rd<uintptr_t>(comps + kComps_SceneComp);
    if (!comp || rd<uintptr_t>(comp) != g_base + g_addrs->vt_scene_comp) return 0;
    const uintptr_t node = rd<uintptr_t>(comp + kSceneComp_Node);
    const uintptr_t so = node > kNode_ToObject ? node - kNode_ToObject : 0;
    if (!so || rd<uintptr_t>(so) != g_base + g_addrs->vt_scene_object || !rd<uintptr_t>(so + kScene_Link)) return 0;
    return so;
}

// The followed vehicle an actor hangs from (at most 4 levels up), or 0.
uint32_t followed_ancestor(uintptr_t table, uint32_t parent_key) noexcept {
    for (int depth = 0; depth < 4 && (parent_key >> 28) == 0xB; ++depth) {
        for (auto& v : g_vehicles)
            if (v.following && v.ts.load() && v.key.load() == parent_key) return parent_key;
        const uintptr_t p = actor_by_key(table, parent_key);
        const uintptr_t pcomps = p ? rd<uintptr_t>(p + kActor_Comps) : 0;
        const uintptr_t phier = pcomps ? rd<uintptr_t>(pcomps + kComps_Hierarchy) : 0;
        parent_key = phier ? rd<uint32_t>(phier + kHier_Parent) : 0;
    }
    return 0;
}

void parts_pass() {
    if (!g_addrs->vt_scene_object) return;
    bool any = false;
    for (auto& v : g_vehicles) any |= v.following && v.ts.load() != 0;
    if (!any && !g_part_count.load()) return;
    for (auto& p : g_parts) p.seen = false;
    const uintptr_t world = rd<uintptr_t>(g_base + g_addrs->world_slot);
    const uintptr_t mgr = world ? rd<uintptr_t>(world + kWorld_Mgr) : 0;
    const uintptr_t table = mgr ? rd<uintptr_t>(mgr + kMgr_Table) : 0;
    const uint32_t n = table ? rd<uint32_t>(table + kTable_Count) : 0;
    const uintptr_t buckets = table ? rd<uintptr_t>(table + kTable_Buckets) : 0, nodes = table ? rd<uintptr_t>(table + kTable_Nodes) : 0;
    if (any && n && n <= (1u << 20) && buckets && nodes) {
        const ULONGLONG now = GetTickCount64();
        for (uint32_t b = 0; b < n; ++b) {
            const uintptr_t base = buckets + static_cast<uintptr_t>(b) * kBucketStride;
            const uint32_t c = rd<uint32_t>(base);
            for (uint32_t i = 0; i < c && i < 31; ++i) {
                const uint32_t key = rd<uint32_t>(base + 8 + i * 8);
                if ((key >> 28) != 0xB) continue;
                const uint32_t idx = rd<uint32_t>(base + 0xC + i * 8);
                const uintptr_t node = rd<uintptr_t>(nodes + static_cast<uintptr_t>(idx) * 8);
                const uintptr_t a = node ? rd<uintptr_t>(node + 8) : 0;
                const uintptr_t info = a ? rd<uintptr_t>(a + kActor_Info) : 0;
                if (!info || rd<uint8_t>(info + 1) != kTypeGimmick) continue;
                const uintptr_t comps = rd<uintptr_t>(a + kActor_Comps);
                const uintptr_t hier = comps ? rd<uintptr_t>(comps + kComps_Hierarchy) : 0;
                if (!hier || rd<uint8_t>(hier + kHier_AttachType) != kAttachSocket) continue;
                const uint32_t parent_key = rd<uint32_t>(hier + kHier_Parent);
                const uint32_t vehicle = followed_ancestor(table, parent_key);
                if (!vehicle) continue;
                Part* part = nullptr;
                for (auto& p : g_parts)
                    if (p.key.load() == key) part = &p;
                if (!part) {
                    for (auto& p : g_parts) {
                        if (p.key.load()) continue;
                        AcquireSRWLockExclusive(&g_parts_lock);
                        p.net_parent = 0;
                        p.net_ms = 0;
                        ReleaseSRWLockExclusive(&g_parts_lock);
                        p.fixes = 0;
                        p.gave_up = p.probe_logged = false;
                        p.key.store(key);
                        part = &p;
                        break;
                    }
                }
                if (!part) continue;  // more socket parts than slots: the rest are not watched
                part->seen = true;
                part->parent = parent_key;
                part->vehicle = vehicle;
                if (part->gave_up) continue;
                uint32_t net_parent = 0;
                float net[3]{};
                ULONGLONG net_ms = 0;
                AcquireSRWLockShared(&g_parts_lock);
                net_parent = part->net_parent;
                std::memcpy(net, part->net_pos, sizeof net);
                net_ms = part->net_ms;
                ReleaseSRWLockShared(&g_parts_lock);
                if (!net_ms || now - net_ms > kPartPoseMaxAgeMs || net_parent != parent_key) continue;
                if (!std::isfinite(net[0]) || !std::isfinite(net[1]) || !std::isfinite(net[2])) continue;
                const uintptr_t so = scene_object(comps);
                const uintptr_t ts = rd<uintptr_t>(comps + kComps_TS);
                if (!so || !ts) continue;
                float local[3]{}, ts_local[3]{};
                int16_t sector[2]{};
                if (!game::fast_read(so + kScene_Local + kXform_Pos, local, sizeof local) ||
                    !game::fast_read(so + kScene_Local + kXform_Sector, sector, sizeof sector) ||
                    !game::fast_read(ts + kTS_LocalPos, ts_local, sizeof ts_local))
                    continue;
                if (sector[0] || sector[1]) continue;                    // not a local transform
                if (dist3(local, ts_local) > kPartSettledM) continue;    // the TS has not caught up with the object yet
                const float off = dist3(local, net);
                if (off <= kPartOffM) continue;
                if (!on()) {
                    if (!part->probe_logged)
                        log::info("VehicleFollow (probe): part 0x{:08X} (on 0x{:08X}, ship 0x{:08X}) is at local ({:.2f}, "
                                  "{:.2f}, {:.2f}) here and ({:.2f}, {:.2f}, {:.2f}) on its controller's client ({:.2f} m): "
                                  "not moved", key, parent_key, vehicle, local[0], local[1], local[2], net[0], net[1],
                                  net[2], off);
                    part->probe_logged = true;
                    continue;
                }
                if (part->fixes >= kMaxPartFixes) {
                    part->gave_up = true;
                    log::warn("VehicleFollow: part 0x{:08X} (on 0x{:08X}) moved away from its controller's place {} times; "
                              "left alone from now on", key, parent_key, part->fixes);
                    continue;
                }
                // The same object still (its vtable and the actor's key), then the 12 bytes.
                if (rd<uintptr_t>(so) != g_base + g_addrs->vt_scene_object || rd<uint32_t>(a + kActor_Key) != key) continue;
                if (!write_bytes(so + kScene_Local + kXform_Pos, net, sizeof net)) continue;
                ++part->fixes;
                g_part_fixes.fetch_add(1, std::memory_order_relaxed);
                log::info("VehicleFollow: part 0x{:08X} (on 0x{:08X}, ship 0x{:08X}) was at local ({:.2f}, {:.2f}, {:.2f}) "
                          "on this client; its controller has it at ({:.2f}, {:.2f}, {:.2f}), {:.2f} m away: moved there "
                          "(scene object; time {} of at most {})", key, parent_key, vehicle, local[0], local[1],
                          local[2], net[0], net[1], net[2], off, part->fixes, kMaxPartFixes);
            }
        }
    }
    uint32_t count = 0;
    for (auto& p : g_parts) {
        if (!p.key.load()) continue;
        if (p.seen)
            ++count;
        else
            p.key.store(0);  // the part or its ship is gone
    }
    g_part_count.store(count);
}

// ---------------------------------------------------------------- passengers: the worker's side
uintptr_t actor_table() noexcept {
    const uintptr_t world = rd<uintptr_t>(g_base + g_addrs->world_slot);
    const uintptr_t mgr = world ? rd<uintptr_t>(world + kWorld_Mgr) : 0;
    return mgr ? rd<uintptr_t>(mgr + kMgr_Table) : 0;
}

// Every 3 s: the other players' characters in the table (0xA keys that are not this client's own actor).
void passengers_list() {
    if (g_addrs->char_request_type == kRequestNone) return;
    const uintptr_t world = rd<uintptr_t>(g_base + g_addrs->world_slot);
    const uintptr_t mgr = world ? rd<uintptr_t>(world + kWorld_Mgr) : 0;
    const uintptr_t table = mgr ? rd<uintptr_t>(mgr + kMgr_Table) : 0;
    const uintptr_t own = mgr ? rd<uintptr_t>(mgr + kMgr_OwnActor) : 0;
    const uint32_t n = table ? rd<uint32_t>(table + kTable_Count) : 0;
    const uintptr_t buckets = table ? rd<uintptr_t>(table + kTable_Buckets) : 0, nodes = table ? rd<uintptr_t>(table + kTable_Nodes) : 0;
    if (!own || !n || n > (1u << 20) || !buckets || !nodes) return;
    for (uint32_t b = 0; b < n; ++b) {
        const uintptr_t base = buckets + static_cast<uintptr_t>(b) * kBucketStride;
        const uint32_t c = rd<uint32_t>(base);
        for (uint32_t i = 0; i < c && i < 31; ++i) {
            const uint32_t key = rd<uint32_t>(base + 8 + i * 8);
            if ((key >> 28) != 0xA) continue;
            const uint32_t idx = rd<uint32_t>(base + 0xC + i * 8);
            const uintptr_t node = rd<uintptr_t>(nodes + static_cast<uintptr_t>(idx) * 8);
            const uintptr_t a = node ? rd<uintptr_t>(node + 8) : 0;
            if (!a || a == own || rd<uint32_t>(a + kActor_Key) != key) continue;
            bool known = false;
            for (auto& p : g_passengers) known |= p.key.load() == key;
            if (known) continue;
            for (auto& p : g_passengers) {
                if (p.key.load()) continue;
                AcquireSRWLockExclusive(&p.lock);
                p.parent = 0;
                p.eased_for = 0;
                p.drawn_ms = 0;
                ReleaseSRWLockExclusive(&p.lock);
                p.chain_for = 0;
                p.chain_len = 0;
                p.vehicle = 0;
                p.moves = p.requests = p.placed = p.unreadable = p.idle_placed = p.idle_failed = 0;
                p.last_off_cm = p.max_off_cm = 0;
                p.request_ms = 0;
                p.channel_ms = 0;
                p.channel_states = 0;
                p.flag_a = p.flag_b = p.rot_flag = 0;
                p.rot_type = kRequestNone;
                p.logged_parent = 0;
                p.ts.store(0);
                p.key.store(key);
                g_passenger_count.fetch_add(1);
                log::info("VehicleFollow: another player's character 0x{:08X} is here; while it stands on a ship part "
                          "it is drawn on this client's copy of that part", key);
                break;
            }
        }
    }
}

// Every 250 ms: each listed character's TransformSync and, for the parent of its last Move, the chain of
// TransformSyncs up to the root vehicle. True: a character is on a ship part (the hooks are wanted).
bool passengers_tick() {
    if (!g_passenger_count.load()) return false;
    const uintptr_t table = actor_table();
    if (!table) return false;
    {
        const uintptr_t world = rd<uintptr_t>(g_base + g_addrs->world_slot);
        const uintptr_t mgr = world ? rd<uintptr_t>(world + kWorld_Mgr) : 0;
        const uintptr_t own = mgr ? rd<uintptr_t>(mgr + kMgr_OwnActor) : 0;
        const uintptr_t own_comps = own ? rd<uintptr_t>(own + kActor_Comps) : 0;
        const uintptr_t own_ts = own_comps ? rd<uintptr_t>(own_comps + kComps_TS) : 0;
        g_own_ts.store(own_ts && rd<uintptr_t>(own_ts + kTS_Actor) == own ? own_ts : 0, std::memory_order_relaxed);
    }
    bool any = false;
    for (auto& p : g_passengers) {
        const uint32_t key = p.key.load();
        if (!key) continue;
        const uintptr_t a = actor_by_key(table, key);
        const uintptr_t comps = a ? rd<uintptr_t>(a + kActor_Comps) : 0;
        const uintptr_t ts = comps ? rd<uintptr_t>(comps + kComps_TS) : 0;
        if (!ts || rd<uintptr_t>(ts + kTS_Actor) != a) {
            if (p.logged_parent || p.placed.load())
                log::info("VehicleFollow: character 0x{:08X} gone; {} of its Moves seen, {} requests on a ship part, {} "
                          "placed, {} more given while it stood still, the game's own pose up to {:.1f} m away", key,
                          p.moves.load(), p.requests.load(), p.placed.load(), p.idle_placed.load(),
                          p.max_off_cm.load() / 100.0);
            p.ts.store(0);
            p.chain_for = 0;
            p.key.store(0);
            g_passenger_count.fetch_sub(1);
            continue;
        }
        p.ts.store(ts, std::memory_order_release);
        uint32_t parent = 0;
        AcquireSRWLockShared(&p.lock);
        parent = p.parent;
        ReleaseSRWLockShared(&p.lock);
        uint32_t len = 0, vehicle = 0;
        std::array<uintptr_t, kMaxChain> chain{};
        uint32_t k = parent;
        for (uint32_t depth = 0; k && depth < kMaxChain; ++depth) {
            const uintptr_t pa = actor_by_key(table, k);
            const uintptr_t pinfo = pa ? rd<uintptr_t>(pa + kActor_Info) : 0;
            const uintptr_t pcomps = pa ? rd<uintptr_t>(pa + kActor_Comps) : 0;
            const uintptr_t pts = pcomps ? rd<uintptr_t>(pcomps + kComps_TS) : 0;
            if (!pinfo || !pts || rd<uintptr_t>(pts + kTS_Actor) != pa) break;
            const uint8_t type = rd<uint8_t>(pinfo + 1);
            if (depth == 0 && type != kTypeGimmick) break;  // on a horse or another character: not here
            chain[depth] = pts;
            const uintptr_t phier = rd<uintptr_t>(pcomps + kComps_Hierarchy);
            const uint32_t up = phier ? rd<uint32_t>(phier + kHier_Parent) : 0;
            if (!up) {
                if (type == kTypeVehicle) {
                    len = depth + 1;
                    vehicle = k;
                }
                break;
            }
            k = up;
        }
        if (len) {
            if (p.chain_for.load() != parent) {
                p.chain_for.store(0, std::memory_order_release);
                for (uint32_t i = 0; i < kMaxChain; ++i) p.chain[i].store(chain[i], std::memory_order_relaxed);
                p.chain_len.store(len, std::memory_order_relaxed);
                p.vehicle.store(vehicle);
                p.chain_for.store(parent, std::memory_order_release);
            } else {
                for (uint32_t i = 0; i < kMaxChain; ++i) p.chain[i].store(chain[i], std::memory_order_relaxed);
            }
            any = true;
            if (p.logged_parent != parent) {
                log::info("VehicleFollow: character 0x{:08X} stands on 0x{:08X} (vehicle 0x{:08X}, {} level{} up): {} on "
                          "this client's copy of it", key, parent, vehicle, len, len == 1 ? "" : "s",
                          on() ? "drawn" : "measured (probe), not placed,");
                p.logged_parent = parent;
            }
        } else {
            p.chain_for.store(0, std::memory_order_release);
            if (p.logged_parent) {
                log::info("VehicleFollow: character 0x{:08X} left 0x{:08X}; {} requests there, {} placed, {} more given "
                          "while it stood still, the game's own pose up to {:.1f} m away", key, p.logged_parent,
                          p.requests.load(), p.placed.load(), p.idle_placed.load(), p.max_off_cm.load() / 100.0);
                p.logged_parent = 0;
                p.max_off_cm = 0;
            }
        }
    }
    return any;
}

// The other player's Move (Ack on the guest, user 2's Req on the host; the same leading layout): the parent and the
// local pose of a listed character.
void passenger_move(std::span<const uint8_t> payload, const movement::Layout& l, uint32_t key) noexcept {
    for (auto& p : g_passengers) {
        if (p.key.load(std::memory_order_relaxed) != key) continue;
        p.moves.fetch_add(1, std::memory_order_relaxed);
        // The other mod says what it stands on 20 times a second: the game's Move is only the fallback.
        if (GetTickCount64() - p.channel_ms.load(std::memory_order_relaxed) < kChannelFreshMs) return;
        uint64_t parent = 0;
        float pos[3], q[4];
        std::memcpy(&parent, payload.data() + l.parent, 8);
        std::memcpy(pos, payload.data() + l.local_pos, sizeof pos);
        std::memcpy(q, payload.data() + l.local_quat, sizeof q);
        const bool ok = parent != ~0ull && (parent >> 32) == 0 && vfl::unit_quat(q) && std::isfinite(pos[0]) &&
                        std::isfinite(pos[1]) && std::isfinite(pos[2]);
        AcquireSRWLockExclusive(&p.lock);
        p.parent = ok ? static_cast<uint32_t>(parent) : 0;
        if (ok) {
            std::memcpy(p.pos, pos, sizeof pos);
            std::memcpy(p.q, q, sizeof q);
        }
        ReleaseSRWLockExclusive(&p.lock);
        return;
    }
}

void refresh(const std::vector<Found>& found) {
    std::string gone, listed;
    for (auto& v : g_vehicles) {
        const uintptr_t ts = v.ts.load();
        if (!ts) continue;
        const Found* f = nullptr;
        for (const auto& c : found)
            if (c.ts == ts && c.vehicle == v.key.load()) f = &c;
        if (f) {
            v.gimmicks = f->gimmicks;
            continue;
        }
        if (v.following)
            log::info("VehicleFollow: vehicle 0x{:08X} (gimmick 0x{:08X}) gone; followed {} positions / {} rotations of {} "
                      "requests, {} samples, error max {:.1f} m", v.key.load(), v.gimmick, v.positions.load(),
                      v.rotations.load(), v.requests.load(), v.samples.load(), v.max_err_cm.load() / 100.0);
        else
            gone += std::format(" 0x{:08X}", v.key.load());
        v.ts.store(0, std::memory_order_release);
    }
    for (const auto& f : found) {
        bool known = false;
        for (auto& v : g_vehicles) known |= v.ts.load() == f.ts && v.key.load() == f.vehicle;
        if (known) continue;
        for (auto& v : g_vehicles) {
            if (v.ts.load()) continue;
            AcquireSRWLockExclusive(&v.lock);
            v.track.clear();
            v.track.set_delay(g_delay_ms.load());
            v.drawn_ms = 0;
            ReleaseSRWLockExclusive(&v.lock);
            v.gimmick = f.gimmick;
            v.gimmicks = f.gimmicks;
            v.following = false;
            v.requests = v.positions = v.rotations = v.samples = 0;
            v.last_err_cm = v.max_err_cm = 0;
            v.key.store(f.vehicle);
            v.ts.store(f.ts, std::memory_order_release);
            listed += std::format(" 0x{:08X} ({} gimmick{}, e.g. 0x{:08X})", f.vehicle, f.gimmicks,
                                  f.gimmicks == 1 ? "" : "s", f.gimmick);
            break;
        }
    }
    if (!listed.empty())
        log::info("VehicleFollow: listed vehicles of another user with vehicle gimmicks:{}; each is followed only while "
                  "it is drawn from one (a ship out: its per-frame vehicle requests)", listed);
    if (!gone.empty()) log::info("VehicleFollow: unlisted (gone, never followed):{}", gone);
}

void announce(Vehicle& v, const char* how) {
    v.following = true;
    vfl::Pose net;
    const bool ok = network_pose(v.ts.load(), &net);
    log::info("VehicleFollow: vehicle 0x{:08X} of another user is drawn from its vehicle gimmick ({}; {} hang from it, "
              "e.g. 0x{:08X}): following it; network pose {}", v.key.load(), how, v.gimmicks, v.gimmick,
              ok ? std::format("({:.1f}, {:.1f}, {:.1f})", net.x, net.y, net.z) : std::string("none yet"));
}

// Before the hooks exist: is any listed vehicle drawn from its gimmick? Such a vehicle gets a vehicle position request
// every frame and the type waits at TS+0x5BC until the TransformSync tick consumes it (~2% of the time on the guest,
// 13-nov); a stabled horse's never shows 7 (4 s of polling, none). Polled for kProbeMs, a few frames.
bool probe_active() {
    std::array<uintptr_t, kMaxVehicles> ts{};
    bool any_listed = false;
    for (size_t i = 0; i < kMaxVehicles; ++i) {
        if (g_vehicles[i].following) continue;
        ts[i] = g_vehicles[i].ts.load();
        any_listed |= ts[i] != 0;
    }
    if (!any_listed) return false;
    const ULONGLONG end = GetTickCount64() + kProbeMs;
    for (uint32_t spin = 0;; ++spin) {
        for (size_t i = 0; i < kMaxVehicles; ++i) {
            if (!ts[i] || !vehicle_request(rd<uint8_t>(ts[i] + kTS_RequestType, kRequestNone))) continue;
            announce(g_vehicles[i], "a vehicle request pending at TS+0x5BC");
            return true;
        }
        YieldProcessor();
        if ((spin & 0xFF) == 0 && GetTickCount64() >= end) return false;
    }
}

DWORD WINAPI worker(LPVOID) {
    try {
        for (int i = 0; i < 2400; ++i) {
            if (rd<uintptr_t>(g_base + g_addrs->world_slot)) break;
            Sleep(500);
        }
        std::vector<gad::Section> secs;
        if (!p8_exe_sections(g_base, secs)) {
            log::error("VehicleFollow: the exe's sections are unreadable; not installed");
            return 0;
        }
        log::info("VehicleFollow ({}, vehicle_follow={}): looking for the other player's ships every 3 s while in the "
                  "world (never during a load); the two setters are hooked only when the first one is out",
                  g_guest.load() ? "guest" : "host", gil::mode_name(static_cast<gil::Mode>(g_mode.load())));
        bool hooked = false;
        uint64_t last_total = 0;
        ULONGLONG last_summary = GetTickCount64();
        uint32_t last_own = 0;
        bool dropped_logged = false;
        bool passengers = false;
        for (uint32_t tick = 0;; ++tick) {
            Sleep(250);
            if (!in_world()) continue;  // the vehicles already followed keep their entries (pointers only)
            if (tick % 12 != 0) {
                // Between two scans: only the passengers' chains (a few table lookups), and their hooks if not in yet.
                passengers = passengers_tick();
                if (hooked || !passengers) continue;
            }
            uint32_t own = 0, dropped = 0;
            const auto found = scan(&own, &dropped);
            if (own != last_own) {
                log::info("VehicleFollow: this client's user 0x{:08X}", own);
                last_own = own;
            }
            if (dropped && !dropped_logged) {
                log::warn("VehicleFollow: more than {} vehicles of another user; {} not listed", kMaxVehicles, dropped);
                dropped_logged = true;
            }
            refresh(found);
            passengers_list();
            passengers = passengers_tick();
            // The setters run for every actor, many times a frame: hooked only once a listed vehicle is drawn from its
            // gimmick (a ship out) or the other player's character stands on a ship part, never during the world loads
            // before it.
            if (!hooked && (passengers || probe_active())) {
                const bool a = p8_install_mid(g_base, secs, g_addrs->set_position, kPatch, kSetPositionHead, &position_mid,
                                              g_pos_hook, "VehicleFollow", "the TransformSync position request");
                const bool b = a && p8_install_mid(g_base, secs, g_addrs->set_rotation, kPatch, kSetRotationHead, &rotation_mid,
                                                   g_rot_hook, "VehicleFollow", "the TransformSync rotation request");
                if (!a || !b) {
                    g_pos_hook = {};
                    g_rot_hook = {};
                    log::error("VehicleFollow: not both setters could be hooked; nothing installed (stopped)");
                    return 0;
                }
                hooked = true;
                log::info("VehicleFollow: hooked exe+0x{:X} / exe+0x{:X}; the other player's ships are {} {} ms behind "
                          "its samples", g_addrs->set_position, g_addrs->set_rotation, on() ? "drawn" : "measured (probe), not moved,",
                          g_delay_ms.load());
            }
            if (hooked)
                for (auto& v : g_vehicles)
                    if (v.ts.load() && !v.following && v.requests.load()) announce(v, "vehicle requests in the hook");
            parts_pass();
            const ULONGLONG now = GetTickCount64();
            if (now - last_summary < 60000) continue;
            last_summary = now;
            uint64_t total = 0;
            std::string line;
            size_t idle = 0;
            for (auto& v : g_vehicles) {
                if (!v.ts.load()) continue;
                if (!v.following) {
                    ++idle;
                    continue;
                }
                total += v.requests.load();
                vfl::Pose d;
                AcquireSRWLockShared(&v.lock);
                d = v.drawn;
                const size_t n = v.track.size();
                ReleaseSRWLockShared(&v.lock);
                line += std::format(" | 0x{:08X} (gimmick 0x{:08X}): requests {} followed {}/{} samples {} (kept {}) "
                                    "drawn ({:.1f}, {:.1f}) error now {:.1f} m max {:.1f} m",
                                    v.key.load(), v.gimmick, v.requests.load(), v.positions.load(), v.rotations.load(),
                                    v.samples.load(), n, d.x, d.z, v.last_err_cm.load() / 100.0,
                                    v.max_err_cm.load() / 100.0);
            }
            for (auto& p : g_passengers) {
                // Only a character that has been on a ship part: its Moves alone do not make a line every minute.
                if (!p.key.load() || !(p.requests.load() + p.idle_placed.load())) continue;
                total += p.requests.load() + p.idle_placed.load();
                line += std::format(" | character 0x{:08X}: Moves {} channel states {} on a ship part now {} own requests {} placed {} "
                                    "given while still {} (faults {}, unreadable {}) rotation type {} the game's own "
                                    "pose {:.1f} m away now, max {:.1f} m",
                                    p.key.load(), p.moves.load(), p.channel_states.load(),
                                    p.chain_for.load() ? "yes" : "no", p.requests.load(),
                                    p.placed.load(), p.idle_placed.load(), p.idle_failed.load(), p.unreadable.load(),
                                    p.rot_type.load(), p.last_off_cm.load() / 100.0, p.max_off_cm.load() / 100.0);
            }
            if (total == last_total && line.empty()) continue;
            last_total = total;
            log::info("VehicleFollow summary ({}, vehicle_follow={}): unreadable network poses {}, {} listed vehicle(s) "
                      "not drawn from a gimmick; socket parts watched {} (their controller's poses received {}, moved "
                      "{}){}", g_guest.load() ? "guest" : "host",
                      gil::mode_name(static_cast<gil::Mode>(g_mode.load())), g_unreadable.load(), idle,
                      g_part_count.load(), g_part_acks.load(), g_part_fixes.load(),
                      line.empty() ? std::string(" | no ship of another user followed") : line);
        }
    } catch (...) {
        log::error("VehicleFollow: the worker stopped (exception)");
    }
    return 0;
}

}  // namespace

bool vehicle_follow_own_anchor(uint32_t* self_key, uint32_t* anchor, float pos[3], float quat[4]) noexcept {
    *self_key = *anchor = 0;
    if (!g_started.load(std::memory_order_relaxed) || !g_addrs || g_addrs->char_request_type == kRequestNone || !in_world())
        return false;
    const uintptr_t world = rd<uintptr_t>(g_base + g_addrs->world_slot);
    const uintptr_t mgr = world ? rd<uintptr_t>(world + kWorld_Mgr) : 0;
    const uintptr_t own = mgr ? rd<uintptr_t>(mgr + kMgr_OwnActor) : 0;
    const uintptr_t comps = own ? rd<uintptr_t>(own + kActor_Comps) : 0;
    const uintptr_t ts = comps ? rd<uintptr_t>(comps + kComps_TS) : 0;
    if (!ts || rd<uintptr_t>(ts + kTS_Actor) != own) return false;
    const uint32_t key = rd<uint32_t>(own + kActor_Key);
    if ((key >> 28) != 0xA) return false;
    *self_key = key;
    const uintptr_t hier = rd<uintptr_t>(comps + kComps_Hierarchy);
    const uint32_t parent = hier ? rd<uint32_t>(hier + kHier_Parent) : 0;
    if ((parent >> 28) != 0xB) return true;  // on nothing: the key alone
    float p[3], q[4];
    int16_t sector[2];
    if (!game::fast_read(ts + kTS_LocalPos, p, sizeof p) || !game::fast_read(ts + kTS_LocalQuat, q, sizeof q) ||
        !game::fast_read(ts + kTS_LocalSector, sector, sizeof sector))
        return true;
    // Local to its parent: no sector, a few metres at most, a unit rotation. Anything else is not sent.
    if (sector[0] || sector[1] || !vfl::unit_quat(q)) return true;
    for (const float v : p)
        if (!std::isfinite(v) || std::fabs(v) > 500.0f) return true;
    *anchor = parent;
    std::memcpy(pos, p, sizeof p);
    std::memcpy(quat, q, sizeof q);
    return true;
}

void vehicle_follow_on_peer_state(uint32_t self_key, uint32_t anchor, const float pos[3], const float quat[4]) noexcept {
    if (!self_key || !g_passenger_count.load(std::memory_order_relaxed)) return;
    for (auto& p : g_passengers) {
        if (p.key.load(std::memory_order_relaxed) != self_key) continue;
        const bool ok = (anchor >> 28) == 0xB && vfl::unit_quat(quat) && std::isfinite(pos[0]) && std::isfinite(pos[1]) &&
                        std::isfinite(pos[2]) && std::fabs(pos[0]) <= 500.0f && std::fabs(pos[1]) <= 500.0f &&
                        std::fabs(pos[2]) <= 500.0f;
        AcquireSRWLockExclusive(&p.lock);
        p.parent = ok ? anchor : 0;
        if (ok) {
            std::memcpy(p.pos, pos, sizeof p.pos);
            std::memcpy(p.q, quat, sizeof p.q);
        }
        ReleaseSRWLockExclusive(&p.lock);
        p.channel_ms.store(GetTickCount64(), std::memory_order_relaxed);
        p.channel_states.fetch_add(1, std::memory_order_relaxed);
        return;
    }
}

void vehicle_follow_on_user2_req(uint16_t opcode, std::span<const uint8_t> payload) noexcept {
    if (opcode != kOpMoveActorReq || !g_passenger_count.load(std::memory_order_relaxed)) return;
    const auto* l = movement::layout(game::current_build());
    if (!l || payload.size() != l->move_req) return;
    uint32_t key = 0;
    std::memcpy(&key, payload.data(), 4);
    if ((key >> 28) == 0xA) passenger_move(payload, *l, key);
}

void vehicle_follow_on_in(uint16_t opcode, std::span<const uint8_t> payload) noexcept {
    if (opcode != kOpMoveActorAck ||
        (!g_part_count.load(std::memory_order_relaxed) && !g_passenger_count.load(std::memory_order_relaxed)))
        return;
    const auto* l = movement::layout(game::current_build());
    if (!l || payload.size() != l->move_ack) return;
    uint32_t key = 0;
    std::memcpy(&key, payload.data(), 4);
    if ((key >> 28) == 0xA) {
        passenger_move(payload, *l, key);
        return;
    }
    if ((key >> 28) != 0xB) return;
    for (auto& p : g_parts) {
        if (p.key.load(std::memory_order_relaxed) != key) continue;
        uint64_t parent = 0;
        float pos[3];
        std::memcpy(&parent, payload.data() + l->parent, 8);
        std::memcpy(pos, payload.data() + l->local_pos, sizeof pos);
        AcquireSRWLockExclusive(&g_parts_lock);
        p.net_parent = parent == ~0ull ? 0 : static_cast<uint32_t>(parent);
        std::memcpy(p.net_pos, pos, sizeof pos);
        p.net_ms = GetTickCount64();
        ReleaseSRWLockExclusive(&g_parts_lock);
        g_part_acks.fetch_add(1, std::memory_order_relaxed);
        return;
    }
}

void vehicle_follow_start(const std::string& mode, bool guest, uint32_t delay_ms) {
    const auto m = gil::parse_mode(mode);
    if (!m) {
        log::warn("VehicleFollow: vehicle_follow '{}' is not 0 | probe | 1; it stays off", mode);
        return;
    }
    if (*m == gil::Mode::Off) return;
    const Addrs* addrs = game::is_3576() ? &kAddrs3576 : game::is_3663() ? &kAddrs3663 : nullptr;
    if (!addrs) {
        log::warn("VehicleFollow: vehicle_follow is for builds 3576 and 3663 only; off");
        return;
    }
    if (g_started.exchange(true)) return;
    g_addrs = addrs;
    if (addrs == &kAddrs3663)
        log::info("VehicleFollow: build 1.0.0.3663: vehicle requests of types {} (near) and {} (far) are followed; the "
                  "setters' bytes are checked before hooking", addrs->request_type, addrs->request_type_far);
    g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    g_guest.store(guest);
    g_mode.store(static_cast<uint8_t>(*m));
    g_delay_ms.store(std::clamp<uint32_t>(delay_ms, 0, 3000));
    log::info("VehicleFollow ON ({}, vehicle_follow={}, delay {} ms): hooked once a ship of another user is found",
              guest ? "guest" : "host", gil::mode_name(*m), g_delay_ms.load());
    CloseHandle(CreateThread(nullptr, 0, worker, nullptr, 0, nullptr));
}

}  // namespace cdmp::session2
