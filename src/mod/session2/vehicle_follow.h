#pragma once
// [session2] vehicle_follow = 0 (default) | probe | 1, either PC (builds 1.0.0.3576 and, static only, 3663). docs/ESTADO-3527.md
// "13-nov: BARCO"; the pure part (smoothing, sector form): vehicle_follow_logic.h.
//
// The other player's ship. Each client simulates its own copy of it; this client's copy follows only the replayed
// helmsman actions and drifts away (no sail/speed state, and the client never applies MoveActorAck to a type-7 actor).
// The ship gimmick (type 7, ClientVehicleActorComponent) hangs in the hierarchy (attach type 7) from the vehicle actor
// (type 5, pa::ClientChildOnlyInGameActor), whose TransformSync the client asks every frame, with a position and a
// rotation request of type 7 (0xB03BB0 / 0xB03FB0 from its character update), to sit on the local ship; the ship is
// then drawn from that parent. The vehicle actor's last network pose (the controller's, ~1 Hz) is in its TransformSync
// at +0x550 (world vec3) / +0x55C (quaternion).
//
// With 1, for vehicles of a ship whose controller (+0x90) is not this client's user, those two requests get a pose
// drawn vehicle_follow_delay_ms (300) behind the controller's samples (interpolated, extrapolated up to 1 s past the
// newest; vfl::Track; about the delay its character is drawn with, so it stays on the wheel): the ship, its parts and what stands on it are
// drawn where the controller has them. Nothing else is touched: the local ship's physics body still runs underneath
// (its collision stays where this client's own simulation has it). probe: the same detection and the same pose,
// measured against the local one, never written.
// Which vehicles: every type-5 ChildOnly actor of another user that a vehicle gimmick hangs from (attach type 7), one
// entry each. Most are the other player's stabled horses with ten-odd gear gimmicks each, which never get a type-7
// request; the one with a ship out gets one every frame, and only those requests are touched.
// Mechanism: two mid hooks at the setters' entries (verified bytes, 5-byte patch), installed only when a listed vehicle
// is drawn from its gimmick (its pending request type, TS+0x5BC, seen at 7 for a few frames of polling; never during
// the world loads before it); the list is rebuilt every 3 s by a worker from the actor table while the client is in
// the world (load state 0x18; never during a load), with SEH-guarded reads; the hooks only compare pointers.
// Lines 'VehicleFollow ...': the vehicles listed or unlisted, the install, each vehicle followed (and its counts when
// it goes), a summary every 60 s while something happens.

//
// Request types (3663, live 2026-11-14): 7 every frame while this client is near the ship (as on 3576), 12 a few times a
// second while it is far away; both are followed on 3663 (3576: 7 only, the far one was never looked at).
// The ship's parts (3663 only): a gimmick attached by a socket under a followed vehicle (the ship's wheel on its mount)
// is created on the other client with its offset from the vehicle instead of from its parent (the wheel floats 2.9 m
// above the deck). Its controller's local position arrives in its MoveActorAck (vehicle_follow_on_in, guest side); when
// the part's scene object is more than 0.25 m off, the position is written once into the scene object
// ([[comps+0x30]+0x18]-0x28, local transform at +0x1D0). 'VehicleFollow: part ...' lines; probe: logged only.
// Passengers (3663 only, both PCs): the client draws the other player's character at the world pose of its Moves, never
// attached to this client's copy of what it stands on: a passenger standing still on a sailing ship stays behind in
// the water (the host saw the guest 107 m astern at 12.7 m/s), and the helmsman sits 0.3-1.9 m off the wheel. While the
// other player's last Move names a gimmick hanging from a vehicle, its character's own per-frame requests (type 12)
// get the pose of this client's copy of that gimmick composed with the Move's local pose (eased over 120 ms). The
// What it stands on comes from the other PC's mod, 20 times a second, in the mod's own PlayerState (protocol 10:
// vehicle_follow_own_anchor on the sender, vehicle_follow_on_peer_state on the receiver): its hierarchy parent and its
// pose local to it. It has to: for a character on a ship's deck (parent = the hull, a ladder, a deck part) the game's
// server sends the other player BLANK MoveActorAcks (all zeros, 30 a second; 14-nov, guest capture), so the guest saw
// the host stay where it boarded until it took the wheel (a mount parent is the one the server keeps). The game's
// Moves (vehicle_follow_on_in on the guest, vehicle_follow_on_user2_req on the host) are only the fallback when no
// channel state came in the last 2 s.
// 'VehicleFollow: character ...' lines. The host needs vehicle_follow=1 too for this.

#include <cstdint>
#include <span>
#include <string>

namespace cdmp::session2 {

// delay_ms: [session2] vehicle_follow_delay_ms (default 300; 0..3000).
void vehicle_follow_start(const std::string& mode, bool guest, uint32_t delay_ms);
// Guest: every packet of the host before the client gets it (the mod's network thread). Keeps the controller's last
// local position of the watched ship parts (MoveActorAck, logical 2697); nothing else. Off or no part watched: nothing.
void vehicle_follow_on_in(uint16_t opcode, std::span<const uint8_t> payload) noexcept;
// Host: every Req of user 2 as it is queued for the server (the mod's network thread). Keeps user 2's character's last
// parent and local pose (MoveActorReq, logical 2556); nothing else. Off or no other character listed: nothing.
void vehicle_follow_on_user2_req(uint16_t opcode, std::span<const uint8_t> payload) noexcept;
// The mod's own channel (protocol 10), both PCs, the mod's network thread.
// Sender: this client's character's key and, when it stands on something (a hierarchy parent), that actor's key and
// the character's pose local to it. False (nothing to send): the module is off, the build has no passengers, or the
// client is not in the world. anchor 0: on nothing.
bool vehicle_follow_own_anchor(uint32_t* self_key, uint32_t* anchor, float pos[3], float quat[4]) noexcept;
// Receiver: the other player's last state. Kept for the listed character with that key; nothing else.
void vehicle_follow_on_peer_state(uint32_t self_key, uint32_t anchor, const float pos[3], const float quat[4]) noexcept;

}  // namespace cdmp::session2
