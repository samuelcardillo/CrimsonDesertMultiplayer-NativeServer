"""comps.py pid key_hex : the actor's component table (actor+0x68) slots with their RTTI class names (3576), read-only."""
import sys, json
R = r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/'
sys.path.insert(0, R + 'tools/porting')
from live_reader_check import Reader
BASE = 0x140000000
rt = json.load(open(R + 'tools/porting/data/rtti_3576.json'))
names = {int(v['rva'], 0): c['name'] for c in rt['classes'].values() for v in c['vtables']}
r = Reader(int(sys.argv[1])); key = int(sys.argv[2], 16)
world = r.ptr(BASE + 0x71C0100); mgr = r.ptr(world + 0x30); t = r.ptr(mgr + 8); n = r.unpack(t + 0x88, '<I')[0]
b = r.ptr(t + 0x98) + (key % n) * 0x100; c = r.unpack(b, '<I')[0]; a = None
for i in range(min(c, 31)):
    k, idx = r.unpack(b + 8 + i * 8, '<II')
    if k == key: a = r.ptr(r.ptr(r.ptr(t + 0xA0) + idx * 8) + 8)
def cls(p):
    try:
        vt = r.ptr(p); return names.get(vt - BASE)
    except Exception: return None
print('actor', hex(a), cls(a))
comps = r.ptr(a + 0x68)
print('comps', hex(comps), cls(comps))
for off in range(0, 0x300, 8):
    try:
        p = r.ptr(comps + off)
    except Exception: continue
    if p and 0x10000 < p < 0x7fffffffffff:
        nm = cls(p)
        if nm: print(f'  +{off:#05x} {p:#x} {nm}')
