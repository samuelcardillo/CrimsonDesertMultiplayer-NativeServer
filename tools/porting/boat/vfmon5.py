"""vfmon5.py host_pid guest_pid seconds [period]: the vehicle 0xB010000A's current pose (TS +0xB4/+0xC0, quat +0xA4) on both
copies, the host character's local offset on its vehicle, and the gap guest(now) - host(now)."""
import struct as _st
with open(r'D:/SteamLibrary/steamapps/common/Crimson Desert/bin64/CrimsonDesert.exe', 'rb') as _f:
    _h = _f.read(0x400)
_ts = _st.unpack_from('<I', _h, _st.unpack_from('<I', _h, 0x3C)[0] + 8)[0]
# The world slot of the installed build: 1.0.0.3663 (PE 0x6AF5D198) or 1.0.0.3576 (0x6AED2E85).
WORLD_SLOT = {0x6AF5D198: 0x72451C0, 0x6AED2E85: 0x71C0100}[_ts]
import sys, time, math
sys.path.insert(0, r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/tools/porting')
from live_reader_check import Reader
B = 0x140000000
hp, gp, secs = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3]); period = float(sys.argv[4]) if len(sys.argv) > 4 else 0.5
def ts_of(r, key):
    world = r.ptr(B + WORLD_SLOT); mgr = r.ptr(world + 0x30); t = r.ptr(mgr + 8); n = r.unpack(t + 0x88, '<I')[0]
    b = r.ptr(t + 0x98) + (key % n) * 0x100; c = r.unpack(b, '<I')[0]
    for i in range(min(c, 31)):
        k, idx = r.unpack(b + 8 + i * 8, '<II')
        if k == key: return r.ptr(r.ptr(r.ptr(r.ptr(r.ptr(t + 0xA0) + idx * 8) + 8) + 0x68) + 0x1A0)
def pose(r, ts):
    p = r.unpack(ts + 0xB4, '<3f'); s = r.unpack(ts + 0xC0, '<hh'); q = r.unpack(ts + 0xA4, '<4f')
    yaw = math.degrees(2 * math.atan2(q[1], q[3]))
    return (p[0] + s[0] * 1000, p[1], p[2] + s[1] * 1000), yaw
rh, rg = Reader(hp), Reader(gp)
hv, gv, hc, gc = ts_of(rh, 0xB010000A), ts_of(rg, 0xB010000A), ts_of(rh, 0xA0100001), ts_of(rg, 0xA0100001)
t0 = time.time(); prev = None; gaps = []
while time.time() - t0 < secs:
    (H, hy), (G, gy) = pose(rh, hv), pose(rg, gv)
    HC = rh.unpack(hc + 0xB4, '<3f'); GC = rg.unpack(gc + 0xB4, '<3f')
    sp = math.hypot(H[0] - prev[0], H[2] - prev[2]) / period if prev else 0; prev = H
    gap = math.hypot(G[0] - H[0], G[2] - H[2]); gaps.append(gap)
    print(f'{time.time()-t0:6.1f} host ({H[0]:9.1f},{H[2]:8.1f}) yaw {hy:6.1f} {sp:4.1f} m/s | guest ({G[0]:9.1f},{G[2]:8.1f}) yaw {gy:6.1f} '
          f'gap {gap:5.1f} m | helmsman local host ({HC[0]:5.2f},{HC[1]:5.2f},{HC[2]:5.2f}) guest ({GC[0]:5.2f},{GC[1]:5.2f},{GC[2]:5.2f})', flush=True)
    time.sleep(period)
s = sorted(gaps); print(f'n {len(s)} gap median {s[len(s)//2]:.2f} p90 {s[int(len(s)*0.9)]:.2f} max {s[-1]:.2f} m')
