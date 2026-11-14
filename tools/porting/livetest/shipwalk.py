"""shipwalk.py pid [-s stop] [-n steps] [-k vehicle_key_hex] lx lz [lx lz ...]: walk a copy's own character ON the ship
to points given in the ship's frame (the vehicle 0xB010000A's; the hull hangs from it at 0,0,0). The character's
TransformSync position is local to the hull while it stands on it (parent = the hull). Read-only memory; input through
ui.ps1. Prints local positions."""
import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__)).replace('\\', '/')
import sys
sys.path.insert(0, _HERE)
sys.path.insert(0, r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/tools/porting')
from cdbuild import WORLD_SLOT, CAMERA_SLOT  # noqa
import math, subprocess, time
from live_reader_check import Reader

SP = (_HERE).replace('/', '\\')
B = 0x140000000
pid = int(sys.argv[1]); args = sys.argv[2:]
stop, steps, vkey, pts = 0.5, 10, 0xB010000A, []
i = 0
while i < len(args):
    if args[i] == '-s': stop = float(args[i + 1]); i += 2
    elif args[i] == '-n': steps = int(args[i + 1]); i += 2
    elif args[i] == '-k': vkey = int(args[i + 1], 16); i += 2
    else: pts.append((float(args[i]), float(args[i + 1]))); i += 2
r = Reader(pid)
world = r.ptr(B + WORLD_SLOT); mgr = r.ptr(world + 0x30); t = r.ptr(mgr + 8); n = r.unpack(t + 0x88, '<I')[0]


def find(key):
    b = r.ptr(t + 0x98) + (key % n) * 0x100; c = r.unpack(b, '<I')[0]
    for j in range(min(c, 31)):
        k, idx = r.unpack(b + 8 + j * 8, '<II')
        if k == key: return r.ptr(r.ptr(r.ptr(t + 0xA0) + idx * 8) + 8)
    return 0


def rot(q, v):
    x, y, z, w = q; vx, vy, vz = v
    cx, cy, cz = y * vz - z * vy, z * vx - x * vz, x * vy - y * vx
    ccx, ccy, ccz = y * cz - z * cy, z * cx - x * cz, x * cy - y * cx
    return (vx + 2 * w * cx + 2 * ccx, vy + 2 * w * cy + 2 * ccy, vz + 2 * w * cz + 2 * ccz)


veh_ts = r.ptr(r.ptr(find(vkey) + 0x68) + 0x1A0)
me = r.ptr(mgr + 0x50); mcomps = r.ptr(me + 0x68); mts = r.ptr(mcomps + 0x1A0)


def state():
    h = r.ptr(mcomps + 0x1B8); par = r.unpack(h + 0x1C, '<I')[0] if h else 0
    return r.unpack(mts + 0xB4, '<fff'), par


def cam_fwd():
    c = r.ptr(B + CAMERA_SLOT); blk = r.ptr(c + 0x430)
    fx, fy, fz = r.unpack(blk + 0x90, '<fff')
    return fx, fz


def ui(*a):
    subprocess.run(['pwsh', '-NoProfile', '-File', SP + r'\ui.ps1', '-GamePid', str(pid), *a], capture_output=True, text=True)


def turn_local(dx, dz):
    for _ in range(5):
        q = r.unpack(veh_ts + 0xA4, '<4f'); w = rot(q, (dx, 0.0, dz)); fx, fz = cam_fwd()
        want = math.degrees(math.atan2(w[0], w[2])); have = math.degrees(math.atan2(fx, fz))
        ang = (want - have + 540) % 360 - 180
        if abs(ang) < 2.5:
            return
        ui('-Do', 'look', '-Dx', str(int(ang * 7.8)), '-Dy', '0', '-Steps', '8')
        time.sleep(0.3)


for (tx, tz) in pts:
    for i in range(steps):
        (px, py, pz), par = state()
        if not par:
            print('not on the ship (no parent)'); break
        d = math.hypot(tx - px, tz - pz)
        if d <= stop:
            break
        turn_local(tx - px, tz - pz)
        ms = 150 if d < 0.8 else 250 if d < 1.6 else int(min(2000, 250 + (d - 1.6) * 330))
        ui('-Do', 'hold', '-Keys', 'W', '-HoldMs', str(ms))
        time.sleep(0.8)
        (qx, qy, qz), par2 = state()
        print(f'  {i} local ({px:.2f},{py:.2f},{pz:.2f}) d {d:.1f} W {ms} -> ({qx:.2f},{qy:.2f},{qz:.2f}) parent {par2:#x}', flush=True)
    (px, py, pz), par = state()
    print(f'at local ({px:.2f},{py:.2f},{pz:.2f}) parent {par:#x}; to ({tx},{tz}) {math.hypot(tx - px, tz - pz):.2f} m', flush=True)
r.close()
