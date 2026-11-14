"""walk.py pid x z [stop_m] [max_steps] [x z ...more waypoints]: walk a copy's own character to world points with short
W holds, steering by the LIVE player position (TS +0xB4/+0xC0) and the camera's forward. Read-only memory; input goes
through ui.ps1 (refuses unless the game is in the foreground). Prints the final position.
The character runs ~11 m/s after the first half second (3663, 2026-11-14), so holds are short."""
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
pid = int(sys.argv[1])
args = sys.argv[2:]
pts = []
stop, steps = 0.8, 14
# walk.py pid [-s stop] [-n steps] x z [x z ...]
i = 0
while i < len(args):
    if args[i] == '-s':
        stop = float(args[i + 1]); i += 2
    elif args[i] == '-n':
        steps = int(args[i + 1]); i += 2
    else:
        pts.append((float(args[i]), float(args[i + 1]))); i += 2
r = Reader(pid)


def pos():
    world = r.ptr(B + WORLD_SLOT); mgr = r.ptr(world + 0x30); a = r.ptr(mgr + 0x50)
    comps = r.ptr(a + 0x68); ts = r.ptr(comps + 0x1A0)
    h = r.ptr(comps + 0x1B8); par = r.unpack(h + 0x1C, '<I')[0] if h else 0
    o = (0xEC, 0xF8) if par else (0xB4, 0xC0)   # parented (on a ship, a nexus): +0xB4 is local, the world block is +0xEC
    x, y, z = r.unpack(ts + o[0], '<fff'); sx, sz = r.unpack(ts + o[1], '<hh')
    return x + sx * 1000.0, y, z + sz * 1000.0


def cam_fwd():
    c = r.ptr(B + CAMERA_SLOT); blk = r.ptr(c + 0x430)
    fx, fy, fz = r.unpack(blk + 0x90, '<fff')
    return fx, fz


def ui(*a):
    subprocess.run(['pwsh', '-NoProfile', '-File', SP + r'\ui.ps1', '-GamePid', str(pid), *a], capture_output=True, text=True)


def turn_to(tx, tz):
    for _ in range(5):
        px, py, pz = pos(); fx, fz = cam_fwd()
        want = math.degrees(math.atan2(tx - px, tz - pz)); have = math.degrees(math.atan2(fx, fz))
        ang = (want - have + 540) % 360 - 180
        if abs(ang) < 2.5:
            return
        ui('-Do', 'look', '-Dx', str(int(ang * 7.8)), '-Dy', '0', '-Steps', '8')
        time.sleep(0.3)


for (tx, tz) in pts:
    last_d = None
    for i in range(steps):
        px, py, pz = pos(); d = math.hypot(tx - px, tz - pz)
        if d <= stop:
            break
        turn_to(tx, tz)
        ms = 150 if d < 1.2 else 250 if d < 2.5 else int(min(2500, 250 + (d - 2.5) * 110))
        ui('-Do', 'hold', '-Keys', 'W', '-HoldMs', str(ms))
        time.sleep(0.9)
        qx, qy, qz = pos()
        print(f'  {i} ({px:.2f},{pz:.2f}) d {d:.1f} W {ms} -> ({qx:.2f},{qy:.2f},{qz:.2f})', flush=True)
        if math.hypot(qx - px, qz - pz) < 0.15:
            print('  stuck');
            if last_d is not None and abs(last_d - d) < 0.2:
                break
        last_d = d
    px, py, pz = pos()
    print(f'at ({px:.2f},{py:.2f},{pz:.2f}) to ({tx},{tz}) {math.hypot(tx - px, tz - pz):.2f} m', flush=True)
r.close()
