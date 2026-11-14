"""hdiff.py host_pid guest_pid key_hex comp_off size: dump one component (comps+off) of an actor on both copies, 8 bytes a
row, marking rows that differ (pointers shown relative to the object when they point inside it)."""
import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__)).replace('\\', '/')
import sys, struct
sys.path.insert(0, _HERE + '/../livetest')
sys.path.insert(0, r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/tools/porting')
from cdbuild import WORLD_SLOT
from live_reader_check import Reader
B = 0x140000000
def obj(pid, key, off, size):
    r = Reader(pid)
    world = r.ptr(B + WORLD_SLOT); mgr = r.ptr(world + 0x30); t = r.ptr(mgr + 8); n = r.unpack(t + 0x88, '<I')[0]
    b = r.ptr(t + 0x98) + (key % n) * 0x100; c = r.unpack(b, '<I')[0]; a = 0
    for i in range(min(c, 31)):
        k, idx = r.unpack(b + 8 + i * 8, '<II')
        if k == key: a = r.ptr(r.ptr(r.ptr(t + 0xA0) + idx * 8) + 8)
    comps = r.ptr(a + 0x68); o = r.ptr(comps + off) if off >= 0 else a
    return o, r.read(o, size)
key = int(sys.argv[3], 16); off = int(sys.argv[4], 16) if sys.argv[4] != 'actor' else -1; size = int(sys.argv[5], 16)
ho, hb = obj(int(sys.argv[1]), key, off, size); go, gb = obj(int(sys.argv[2]), key, off, size)
print(f'host obj {ho:#x} guest obj {go:#x}')
def show(v, base):
    q = struct.unpack('<Q', v)[0]
    if 0x140000000 <= q < 0x155000000: return f'exe+{q - B:#x}'
    if 0x10000000000 <= q < 0x7FFFFFFFFFFF: return f'ptr{"(self%+#x)" % (q - base) if abs(q - base) < 0x4000 else ""}'
    a, b2 = struct.unpack('<ff', v); u1, u2 = struct.unpack('<II', v)
    return f'{u1:#x} {u2:#x} | {a:.3f} {b2:.3f}'
for o in range(0, size, 8):
    h, g = hb[o:o+8], gb[o:o+8]
    sh, sg = show(h, ho), show(g, go)
    mark = '' if sh == sg else '   <<<'
    print(f'+{o:#05x} host {sh:38s} guest {sg:38s}{mark}')
