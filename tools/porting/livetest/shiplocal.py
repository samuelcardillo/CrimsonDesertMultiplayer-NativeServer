"""shiplocal.py pid lx lz [lx lz ...]: world x z of points given in the frame of the vehicle 0xB010000A on that copy."""
import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__)).replace('\\', '/')
import sys as _sys
_sys.path.insert(0, _HERE)
from cdbuild import WORLD_SLOT, CAMERA_SLOT  # noqa
import sys
sys.path.insert(0, r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/tools/porting')
from live_reader_check import Reader
B = 0x140000000; r = Reader(int(sys.argv[1])); key = 0xB010000A
world = r.ptr(B + WORLD_SLOT); mgr = r.ptr(world + 0x30); t = r.ptr(mgr + 8); n = r.unpack(t + 0x88, '<I')[0]
b = r.ptr(t + 0x98) + (key % n) * 0x100; c = r.unpack(b, '<I')[0]
for i in range(min(c, 31)):
    k, idx = r.unpack(b + 8 + i * 8, '<II')
    if k == key: ts = r.ptr(r.ptr(r.ptr(r.ptr(r.ptr(t + 0xA0) + idx * 8) + 8) + 0x68) + 0x1A0)
p = r.unpack(ts + 0xB4, '<3f'); s = r.unpack(ts + 0xC0, '<hh'); q = r.unpack(ts + 0xA4, '<4f')
sp = (p[0] + s[0] * 1000, p[1], p[2] + s[1] * 1000)
def rot(q, v):
    x, y, z, w = q; vx, vy, vz = v
    cx, cy, cz = y*vz - z*vy, z*vx - x*vz, x*vy - y*vx
    ccx, ccy, ccz = y*cz - z*cy, z*cx - x*cz, x*cy - y*cx
    return (vx + 2*w*cx + 2*ccx, vy + 2*w*cy + 2*ccy, vz + 2*w*cz + 2*ccz)
a = [float(v) for v in sys.argv[2:]]
print(' '.join(f'{sp[0] + rot(q, (a[i], 0, a[i+1]))[0]:.1f} {sp[2] + rot(q, (a[i], 0, a[i+1]))[2]:.1f}' for i in range(0, len(a), 2)))
