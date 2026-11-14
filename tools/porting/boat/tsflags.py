"""tsflags.py host_pid guest_pid key_lo key_hi: TS+0x90 (flags), hierarchy +0x18 (attach), local pos on both copies."""
import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__)).replace('\\', '/')
import sys
sys.path.insert(0, _HERE + '/../livetest')
sys.path.insert(0, r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/tools/porting')
from cdbuild import WORLD_SLOT
from live_reader_check import Reader
B = 0x140000000; lo, hi = int(sys.argv[3], 16), int(sys.argv[4], 16)
def table(pid):
    r = Reader(pid); out = {}
    world = r.ptr(B + WORLD_SLOT); mgr = r.ptr(world + 0x30); t = r.ptr(mgr + 8); n = r.unpack(t + 0x88, '<I')[0]
    buckets = r.ptr(t + 0x98); nodes = r.ptr(t + 0xA0)
    for bi in range(n):
        base = buckets + bi * 0x100; c = r.unpack(base, '<I')[0]
        for i in range(min(c, 31)):
            k, idx = r.unpack(base + 8 + i * 8, '<II')
            if not (lo <= k <= hi or k == 0xB010000A): continue
            try:
                a = r.ptr(r.ptr(nodes + idx * 8) + 8); comps = r.ptr(a + 0x68); ts = r.ptr(comps + 0x1A0); h = r.ptr(comps + 0x1B8)
                inf = r.ptr(a + 0x88); typ = r.unpack(inf + 1, '<B')[0]
                out[k] = (typ, r.unpack(ts + 0x90, '<I')[0], r.unpack(h + 0x18, '<I')[0] if h else 0, r.unpack(h + 0x1C, '<I')[0] if h else 0,
                          tuple(round(v, 2) for v in r.unpack(ts + 0xB4, '<3f')), r.unpack(a, '<Q')[0] - B)
            except Exception as e:
                out[k] = None
    return out
h, g = table(int(sys.argv[1])), table(int(sys.argv[2]))
for k in sorted(set(h) | set(g)):
    a, b = h.get(k), g.get(k)
    f = lambda x: '-' if not x else f't{x[0]} vt {x[5]:#x} flags {x[1]:#08x} attach {x[2]:#06x} par {x[3]:#x} local {x[4]}'
    mark = '  <<< flags' if a and b and a[1] != b[1] else ''
    print(f'{k:#x} host {f(a)}\n           guest {f(b)}{mark}')
