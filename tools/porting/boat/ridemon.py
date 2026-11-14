"""ridemon.py host guest seconds [period]: the ship vehicle on both copies and the guest's own character (parent, local) on
the guest copy, plus the guest's character as the host sees it (0xA0100002 or the key given)."""
import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__)).replace('\\', '/')
import sys, time, math
sys.path.insert(0, _HERE + '/../livetest')
sys.path.insert(0, r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/tools/porting')
from cdbuild import WORLD_SLOT
from live_reader_check import Reader
B = 0x140000000
hp, gp, secs = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3]); period = float(sys.argv[4]) if len(sys.argv) > 4 else 1.0
def setup(pid):
    r = Reader(pid); world = r.ptr(B + WORLD_SLOT); mgr = r.ptr(world + 0x30); t = r.ptr(mgr + 8); n = r.unpack(t + 0x88, '<I')[0]
    def find(key):
        b = r.ptr(t + 0x98) + (key % n) * 0x100; c = r.unpack(b, '<I')[0]
        for i in range(min(c, 31)):
            k, idx = r.unpack(b + 8 + i * 8, '<II')
            if k == key: return r.ptr(r.ptr(r.ptr(t + 0xA0) + idx * 8) + 8)
        return 0
    return r, mgr, find
rh, mh, fh = setup(hp); rg, mg, fg = setup(gp)
def ts_of(r, a): return r.ptr(r.ptr(a + 0x68) + 0x1A0)
def veh(r, find):
    ts = ts_of(r, find(0xB010000A)); p = r.unpack(ts + 0xB4, '<3f'); s = r.unpack(ts + 0xC0, '<hh'); q = r.unpack(ts + 0xA4, '<4f')
    return (p[0] + s[0] * 1000, p[1], p[2] + s[1] * 1000), math.degrees(2 * math.atan2(q[1], q[3]))
def me(r, mgr):
    a = r.ptr(mgr + 0x50); comps = r.ptr(a + 0x68); ts = r.ptr(comps + 0x1A0); h = r.ptr(comps + 0x1B8)
    par = r.unpack(h + 0x1C, '<I')[0] if h else 0
    return par, r.unpack(ts + 0xB4, '<3f'), r.unpack(a + 0x8, '<I')[0] if False else 0
t0 = time.time(); prev = None
while time.time() - t0 < secs:
    (H, hy), (G, gy) = veh(rh, fh), veh(rg, fg)
    par, loc, _ = me(rg, mg)
    sp = math.hypot(H[0] - prev[0], H[2] - prev[2]) / period if prev else 0; prev = H
    print(f'{time.time()-t0:5.1f} host ship ({H[0]:9.1f},{H[1]:6.1f},{H[2]:8.1f}) yaw {hy:6.1f} {sp:4.1f} m/s | guest draws it at gap {math.hypot(G[0]-H[0], G[2]-H[2]):5.1f} m yaw {gy:6.1f} | guest char parent {par:#x} local ({loc[0]:7.2f},{loc[1]:6.2f},{loc[2]:7.2f})', flush=True)
    time.sleep(period)
