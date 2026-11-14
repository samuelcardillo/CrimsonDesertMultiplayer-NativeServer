"""vfmon.py host_pid guest_pid key_hex seconds : the ship's TS pose on both copies every 0.5 s and the gap."""
import sys, time, math
sys.path.insert(0, r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/tools/porting')
from live_reader_check import Reader
B = 0x140000000
hp, gp, key, secs = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3], 16), float(sys.argv[4])
def ts_of(r):
    world = r.ptr(B + 0x71C0100); mgr = r.ptr(world + 0x30); t = r.ptr(mgr + 8); n = r.unpack(t + 0x88, '<I')[0]
    b = r.ptr(t + 0x98) + (key % n) * 0x100; c = r.unpack(b, '<I')[0]
    for i in range(min(c, 31)):
        k, idx = r.unpack(b + 8 + i * 8, '<II')
        if k == key: return r.ptr(r.ptr(r.ptr(r.ptr(r.ptr(t + 0xA0) + idx * 8) + 8) + 0x68) + 0x1A0)
def pose(r, ts):
    p = r.unpack(ts + 0xEC, '<3f'); s = r.unpack(ts + 0xF8, '<hh'); q = r.unpack(ts + 0xDC, '<4f')
    return (p[0] + s[0] * 1000, p[1], p[2] + s[1] * 1000), q
rh, rg = Reader(hp), Reader(gp); th, tg = ts_of(rh), ts_of(rg)
t0 = time.time(); gaps = []
while time.time() - t0 < secs:
    try:
        (ph, qh), (pg, qg) = pose(rh, th), pose(rg, tg)
    except Exception as e:
        print('read failed', e); break
    gap = math.hypot(ph[0] - pg[0], ph[2] - pg[2]); gaps.append(gap)
    yaw = lambda q: math.degrees(2 * math.atan2(q[1], q[3]))
    print(f'{time.time() - t0:6.1f} host ({ph[0]:9.1f},{ph[2]:8.1f}) yaw {yaw(qh):6.1f} | guest ({pg[0]:9.1f},{pg[2]:8.1f}) yaw {yaw(qg):6.1f} | gap {gap:5.1f} m', flush=True)
    time.sleep(0.5)
if gaps:
    s = sorted(gaps); print(f'samples {len(s)} gap median {s[len(s)//2]:.1f} p90 {s[int(len(s)*0.9)]:.1f} max {s[-1]:.1f} m')
