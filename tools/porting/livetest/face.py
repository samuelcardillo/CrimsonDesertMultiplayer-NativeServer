"""Turn a game copy's camera to face a world point (x, z), reading the camera from memory; then optionally walk to it.
usage: face.py pid x z [walk_stop_m]   (input through ui.ps1, which refuses unless the game is in the foreground)"""
import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__)).replace('\\', '/')
import sys as _sys
_sys.path.insert(0, _HERE)
from cdbuild import WORLD_SLOT, CAMERA_SLOT  # noqa
import math
import subprocess
import sys
import time

sys.path.insert(0, r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/tools/porting')
from live_reader_check import Reader

SP = (_HERE).replace('/', '\\')
B = 0x140000000
pid, tx, tz = int(sys.argv[1]), float(sys.argv[2]), float(sys.argv[3])
walk_stop = float(sys.argv[4]) if len(sys.argv) > 4 else 0.0
r = Reader(pid)


def ui(*a):
    subprocess.run(['pwsh', '-NoProfile', '-File', SP + r'\ui.ps1', '-GamePid', str(pid), *a], capture_output=True, text=True)


def cam():
    c = r.ptr(B + CAMERA_SLOT)  # 3576 camera slot (3527/3549: 0x70DA028)
    blk = r.ptr(c + 0x430)
    px, py, pz = r.unpack(blk + 0x80, '<fff')
    fx, fy, fz = r.unpack(blk + 0x90, '<fff')
    return (px, pz), (fx, fz)


def player():
    # The mod's reader: the physics position is not reachable from here simply; use the camera's position as a proxy for
    # the bearing (a third-person camera is ~3 m behind) and the log's Local pos for distance when walking.
    return cam()[0]


for i in range(5):
    (px, pz), (fx, fz) = cam()
    want = math.degrees(math.atan2(tx - px, tz - pz))
    have = math.degrees(math.atan2(fx, fz))
    ang = want - have
    while ang > 180:
        ang -= 360
    while ang < -180:
        ang += 360
    print(f'{i} cam ({px:.1f},{pz:.1f}) fwd {have:.1f} want {want:.1f} turn {ang:.1f} dist {math.hypot(tx - px, tz - pz):.1f}')
    if abs(ang) < 3:
        break
    ui('-Do', 'look', '-Dx', str(int(ang * 7.8)), '-Dy', '0', '-Steps', '10')
    time.sleep(0.4)
if walk_stop > 0:
    for i in range(8):
        (px, pz), _ = cam()
        d = math.hypot(tx - px, tz - pz) - 3.0  # the camera is behind the character
        if d <= walk_stop:
            break
        ui('-Do', 'hold', '-Keys', 'W', '-HoldMs', str(min(2500, max(250, int(d * 300)))))
        time.sleep(0.3)
        (px, pz), (fx, fz) = cam()
        want = math.degrees(math.atan2(tx - px, tz - pz))
        have = math.degrees(math.atan2(fx, fz))
        ang = (want - have + 540) % 360 - 180
        if abs(ang) > 4:
            ui('-Do', 'look', '-Dx', str(int(ang * 7.8)), '-Dy', '0', '-Steps', '8')
            time.sleep(0.3)
    (px, pz), _ = cam()
    print('walked: camera at', round(px, 1), round(pz, 1), 'to target', round(math.hypot(tx - px, tz - pz), 1))
r.close()
