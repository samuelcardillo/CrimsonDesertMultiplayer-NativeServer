"""vfmon3.py host_pid guest_pid ship_hex char_hex seconds : on both copies, the ship (TS +0xEC) and the host character
(TS +0xB4), and the character's offset from the ship; how much the guest's offset differs from the host's."""
import sys, time, math
sys.path.insert(0, r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/tools/porting')
from live_reader_check import Reader
B = 0x140000000
hp, gp, ship, char, secs = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3], 16), int(sys.argv[4], 16), float(sys.argv[5])
def ts_of(r, key):
    world = r.ptr(B + 0x71C0100); mgr = r.ptr(world + 0x30); t = r.ptr(mgr + 8); n = r.unpack(t + 0x88, '<I')[0]
    b = r.ptr(t + 0x98) + (key % n) * 0x100; c = r.unpack(b, '<I')[0]
    for i in range(min(c, 31)):
        k, idx = r.unpack(b + 8 + i * 8, '<II')
        if k == key: return r.ptr(r.ptr(r.ptr(r.ptr(r.ptr(t + 0xA0) + idx * 8) + 8) + 0x68) + 0x1A0)
def wpos(r, ts, po, so):
    p = r.unpack(ts + po, '<3f'); s = r.unpack(ts + so, '<hh'); return (p[0] + s[0] * 1000, p[1], p[2] + s[1] * 1000)
rh, rg = Reader(hp), Reader(gp)
hs, hc, gs, gc = ts_of(rh, ship), ts_of(rh, char), ts_of(rg, ship), ts_of(rg, char)
t0 = time.time(); errs = []
while time.time() - t0 < secs:
    try:
        HS, HC, GS, GC = wpos(rh, hs, 0xEC, 0xF8), wpos(rh, hc, 0xB4, 0xC0), wpos(rg, gs, 0xEC, 0xF8), wpos(rg, gc, 0xB4, 0xC0)
    except Exception as e:
        print('read failed', e); break
    oh = (HC[0] - HS[0], HC[2] - HS[2]); og = (GC[0] - GS[0], GC[2] - GS[2])
    e = math.hypot(oh[0] - og[0], oh[1] - og[1]); errs.append(e)
    sp = math.hypot(*[a - b for a, b in zip((HS[0], HS[2]), getattr(sys.modules[__name__], 'prev', (HS[0], HS[2])))]) / 0.5
    globals()['prev'] = (HS[0], HS[2])
    print(f'{time.time() - t0:6.1f} host ship ({HS[0]:9.1f},{HS[2]:8.1f}) speed {sp:4.1f} m/s | char-ship host ({oh[0]:5.1f},{oh[1]:5.1f}) guest ({og[0]:5.1f},{og[1]:5.1f}) | off by {e:4.1f} m', flush=True)
    time.sleep(0.5)
s = sorted(errs); print(f'samples {len(s)} offset error median {s[len(s)//2]:.1f} p90 {s[int(len(s)*0.9)]:.1f} max {s[-1]:.1f} m')
