"""partlocal.py host_pid guest_pid : each ship part's local TS pose (+0xB4 pos, +0xA4 quat) on both copies, side by side."""
import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__)).replace('\\', '/')
import sys
sys.path.insert(0, r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/tools/porting')
sys.path.insert(0, _HERE + '/../livetest')
from live_reader_check import Reader
from cdbuild import WORLD_SLOT
B = 0x140000000


def table(pid):
    r = Reader(pid)
    world = r.ptr(B + WORLD_SLOT); mgr = r.ptr(world + 0x30); t = r.ptr(mgr + 8); n = r.unpack(t + 0x88, '<I')[0]
    buckets = r.ptr(t + 0x98); nodes = r.ptr(t + 0xA0); out = {}
    for bi in range(n):
        base = buckets + bi * 0x100
        c = r.unpack(base, '<I')[0]
        for i in range(min(c, 31)):
            k, idx = r.unpack(base + 8 + i * 8, '<II')
            if not (0xB0101540 <= k <= 0xB0101570 or k in (0xB010000A, 0xA0100001, 0xA0100002, 0xA0100003, 0xA0100065, 0xA0100066)): continue
            node = r.ptr(nodes + idx * 8); a = r.ptr(node + 8) if node else 0
            if not a: continue
            try:
                comps = r.ptr(a + 0x68); ts = r.ptr(comps + 0x1A0); h = r.ptr(comps + 0x1B8)
                par = r.unpack(h + 0x1C, '<I')[0] if h else 0
                p = r.unpack(ts + 0xB4, '<3f'); q = r.unpack(ts + 0xA4, '<4f')
                out[k] = (par, p, q)
            except Exception as e:
                out[k] = (0, None, None)
    return out


h, g = table(int(sys.argv[1])), table(int(sys.argv[2]))
for k in sorted(set(h) | set(g)):
    hp = h.get(k); gp = g.get(k)
    def fmt(x):
        if not x or x[1] is None: return '-'
        return f'par {x[0]:#x} pos ({x[1][0]:8.2f},{x[1][1]:7.2f},{x[1][2]:8.2f}) q ({x[2][0]:+.2f},{x[2][1]:+.2f},{x[2][2]:+.2f},{x[2][3]:+.2f})'
    diff = ''
    if hp and gp and hp[1] and gp[1]:
        d = max(abs(a - b) for a, b in zip(hp[1], gp[1]))
        diff = f'  DIFF {d:.2f}' if d > 0.5 else ''
    print(f'{k:#x} host {fmt(hp)}\n           guest {fmt(gp)}{diff}')
