"""shipinv.py pid [x z ...]: the ship vehicle's pose on that copy and, in its frame, the copy's own character (or the given
world points)."""
import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__)).replace(chr(92), '/')
import sys, math
sys.path.insert(0, _HERE)
sys.path.insert(0, r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/tools/porting')
from cdbuild import WORLD_SLOT
from live_reader_check import Reader
B = 0x140000000; r = Reader(int(sys.argv[1])); key = 0xB010000A
world = r.ptr(B + WORLD_SLOT); mgr = r.ptr(world + 0x30); t = r.ptr(mgr + 8); n = r.unpack(t + 0x88, '<I')[0]
b = r.ptr(t + 0x98) + (key % n) * 0x100; c = r.unpack(b, '<I')[0]
for i in range(min(c, 31)):
    k, idx = r.unpack(b + 8 + i * 8, '<II')
    if k == key: ts = r.ptr(r.ptr(r.ptr(r.ptr(r.ptr(t + 0xA0) + idx * 8) + 8) + 0x68) + 0x1A0)
p = r.unpack(ts + 0xB4, '<3f'); s = r.unpack(ts + 0xC0, '<hh'); q = r.unpack(ts + 0xA4, '<4f')
ox, oz = p[0] + s[0] * 1000, p[2] + s[1] * 1000; yaw = 2 * math.atan2(q[1], q[3])
print(f'ship origin ({ox:.2f}, {p[1]:.2f}, {oz:.2f}) yaw {math.degrees(yaw):.1f}')
pts = [float(a) for a in sys.argv[2:]]
if not pts:
    a = r.ptr(mgr + 0x50); mts = r.ptr(r.ptr(a + 0x68) + 0x1A0); mp = r.unpack(mts + 0xB4, '<3f'); ms = r.unpack(mts + 0xC0, '<hh')
    pts = [mp[0] + ms[0] * 1000, mp[2] + ms[1] * 1000]
for i in range(0, len(pts), 2):
    dx, dz = pts[i] - ox, pts[i + 1] - oz
    lx = dx * math.cos(yaw) - dz * math.sin(yaw); lz = dx * math.sin(yaw) + dz * math.cos(yaw)
    print(f'world ({pts[i]:.2f}, {pts[i+1]:.2f}) -> ship local ({lx:.2f}, {lz:.2f})')
