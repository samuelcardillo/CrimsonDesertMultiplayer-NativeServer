"""passmon.py host guest host_char_key guest_char_key seconds [period]: how far each client draws the OTHER player's character
from where it stands on the ship (its own client's parent + local pose, taken on this client's copy of that parent)."""
import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__)).replace('\\', '/')
import sys, time, math
sys.path.insert(0, _HERE + '/../livetest')
sys.path.insert(0, r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/tools/porting')
from cdbuild import WORLD_SLOT
from live_reader_check import Reader
B = 0x140000000
hp, gp, hk, gk, secs = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3], 16), int(sys.argv[4], 16), float(sys.argv[5])
period = float(sys.argv[6]) if len(sys.argv) > 6 else 1.0
def rot(q, v):
    x, y, z, w = q; vx, vy, vz = v
    cx, cy, cz = y*vz - z*vy, z*vx - x*vz, x*vy - y*vx
    ccx, ccy, ccz = y*cz - z*cy, z*cx - x*cz, x*cy - y*cx
    return (vx + 2*w*cx + 2*ccx, vy + 2*w*cy + 2*ccy, vz + 2*w*cz + 2*ccz)
def qmul(a, b):
    ax, ay, az, aw = a; bx, by, bz, bw = b
    return (aw*bx + ax*bw + ay*bz - az*by, aw*by - ax*bz + ay*bw + az*bx, aw*bz + ax*by - ay*bx + az*bw, aw*bw - ax*bx - ay*by - az*bz)
class Copy:
    def __init__(self, pid):
        self.r = r = Reader(pid); world = r.ptr(B + WORLD_SLOT); mgr = r.ptr(world + 0x30); t = r.ptr(mgr + 8)
        self.n = r.unpack(t + 0x88, '<I')[0]; self.buckets = r.ptr(t + 0x98); self.nodes = r.ptr(t + 0xA0); self.cache = {}
    def find(self, key):
        if key in self.cache: return self.cache[key]
        r = self.r; b = self.buckets + (key % self.n) * 0x100; c = r.unpack(b, '<I')[0]
        for i in range(min(c, 31)):
            k, idx = r.unpack(b + 8 + i * 8, '<II')
            if k == key:
                a = r.ptr(r.ptr(self.nodes + idx * 8) + 8); comps = r.ptr(a + 0x68)
                self.cache[key] = (r.ptr(comps + 0x1A0), r.ptr(comps + 0x1B8)); return self.cache[key]
        return (0, 0)
    def local(self, key):
        ts, h = self.find(key); r = self.r
        par = r.unpack(h + 0x1C, '<I')[0] if h else 0
        p = r.unpack(ts + 0xB4, '<3f'); s = r.unpack(ts + 0xC0, '<hh'); q = r.unpack(ts + 0xA4, '<4f')
        return par, (p[0] + s[0]*1000, p[1], p[2] + s[1]*1000), q
    def world(self, key, depth=0):
        par, p, q = self.local(key)
        if not par or depth > 5: return p, q
        pp, pq = self.world(par, depth + 1); w = rot(pq, p)
        return (pp[0] + w[0], pp[1] + w[1], pp[2] + w[2]), qmul(pq, q)
H, G = Copy(hp), Copy(gp); t0 = time.time(); prev = None
while time.time() - t0 < secs:
    try:
        # the guest's character: its own client's parent + local; where the HOST's copy of that parent is; where the host draws it
        gpar, gloc, gq = G.local(gk); hpar, hloc, hq = H.local(hk)
        ship, _ = H.world(0xB010000A)
        sp = math.hypot(ship[0] - prev[0], ship[2] - prev[2]) / period if prev else 0; prev = ship
        if gpar:
            pp, pq = H.world(gpar); w = rot(pq, gloc); want = (pp[0] + w[0], pp[1] + w[1], pp[2] + w[2])
        else: want = gloc
        drawn, _ = H.world(gk); eh = math.dist(want, drawn)
        if hpar:
            pp, pq = G.world(hpar); w = rot(pq, hloc); want2 = (pp[0] + w[0], pp[1] + w[1], pp[2] + w[2])
        else: want2 = hloc
        drawn2, _ = G.world(hk); eg = math.dist(want2, drawn2)
        gd, _ = G.world(0xB010000A)
        print(f'{time.time()-t0:5.1f} ship {sp:4.1f} m/s (guest draws it {math.dist(ship, gd):4.1f} m off) | host draws the guest (on {gpar:#x}) {eh:5.2f} m from its place (dy {drawn[1]-want[1]:+.2f}) | guest draws the host (on {hpar:#x}) {eg:5.2f} m from its place (dy {drawn2[1]-want2[1]:+.2f})', flush=True)
    except Exception as e:
        print('err', e)
    time.sleep(period)
