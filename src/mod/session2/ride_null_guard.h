#pragma once
// [session2] ride_null_guard = 1 (default) | 0, host and guest. Build 1.0.0.3663 only.
//
// A character in the riding movement state (0x10 at [[[actor+0x68]+0x20]+0x2F0]) is updated by 0x620590(this, mount
// actor, ...), which reads the mount's state through the mount actor (0x620B19: mov rax,[rbp+0x6F]; mov rax,[rax+0x68])
// without checking it. While a client loads into a world where the other player's ship is out, a rider whose mount has
// not arrived yet gives a null mount there, and the game closes: guest crash of 2026-11-14 06:02 (join with the host's
// ship moored, exe+0x620B1D, read of 0x68, minidump cdmp_crash.guest_20261114-060252), 1 join in 7 that night; the same
// function closed the guest three times on 3576 on 13-nov (0x5F51DD there).
// The guard sends that one case to where the function goes when the character is not riding (0x620B3F, the target of
// the jne two instructions earlier): the update goes on without looking at the mount. It does not explain why the
// mount is missing; the next update, with the mount there, runs as the game wrote it.
// One mid hook over two whole instructions (8 bytes, verified). 'RideNullGuard' lines: installed, and each of the first
// eight times it acts.

namespace cdmp::session2 {

// From the worker at start-up. Its own short thread waits for the world, verifies the code, hooks it and ends.
void ride_null_guard_start(bool enabled, bool guest);

}  // namespace cdmp::session2
