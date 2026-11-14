"""Walk a game copy's character to a world position with the helper's input. usage: goto.py pid x z [stop_m] [max_steps]
Read-only memory; input through ui.ps1, which refuses unless the game is in the foreground."""
import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__)).replace('\\', '/')
import sys as _sys
_sys.path.insert(0, _HERE)
from cdbuild import WORLD_SLOT, CAMERA_SLOT  # noqa
import sys, math, subprocess, time
R = r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/'
sys.path.insert(0, R + 'tools/porting')
from live_reader_check import Reader
SP = (_HERE).replace('/', '\\')
pid, tx, tz = int(sys.argv[1]), float(sys.argv[2]), float(sys.argv[3])
stop = float(sys.argv[4]) if len(sys.argv) > 4 else 4.0
steps = int(sys.argv[5]) if len(sys.argv) > 5 else 12
BASE = 0x140000000
r = Reader(pid)


def pos():
    world = r.ptr(BASE + WORLD_SLOT)
    mgr = r.ptr(world + 0x30)
    a = r.ptr(mgr + 0x50)
    comps = r.ptr(a + 0x68); ts = r.ptr(comps + 0x1A0)
    h = r.ptr(comps + 0x1B8); par = r.unpack(h + 0x1C, '<I')[0] if h else 0
    o = (0xEC, 0xF8) if par else (0xB4, 0xC0)   # parented (on a ship, a nexus): +0xB4 is local, the world block is +0xEC
    x, y, z = r.unpack(ts + o[0], '<fff')
    sx, sz = r.unpack(ts + o[1], '<hh')
    return x + sx * 1000.0, z + sz * 1000.0


def ui(*a):
    subprocess.run(['pwsh', '-NoProfile', '-File', SP + r'\ui.ps1', '-GamePid', str(pid), *a], capture_output=True, text=True)


p0 = pos()
d0 = math.hypot(tx - p0[0], tz - p0[1])
print('start', [round(v, 1) for v in p0], 'dist', round(d0, 1))
for i in range(steps):
    a = pos()
    d = math.hypot(tx - a[0], tz - a[1])
    if d <= stop:
        break
    run = min(4000, max(500, int(d * 170)))
    ui('-Do', 'hold', '-Keys', 'W SHIFT' if d > 12 else 'W', '-HoldMs', str(run))
    time.sleep(0.25)
    b = pos()
    moved = (b[0] - a[0], b[1] - a[1])
    if math.hypot(*moved) < 0.3:
        print('stuck at', [round(v, 1) for v in b]); ui('-Do', 'look', '-Dx', '400', '-Dy', '0', '-Steps', '8'); continue
    want = (tx - b[0], tz - b[1])
    ang = math.degrees(math.atan2(want[0], want[1]) - math.atan2(moved[0], moved[1]))
    while ang > 180:
        ang -= 360
    while ang < -180:
        ang += 360
    print(i, [round(v, 1) for v in b], 'dist', round(math.hypot(*want), 1), 'turn', round(ang, 1))
    ui('-Do', 'look', '-Dx', str(int(ang * 7.8)), '-Dy', '0', '-Steps', '10')
e = pos()
print('end', [round(v, 1) for v in e], 'dist', round(math.hypot(tx - e[0], tz - e[1]), 1))
r.close()
