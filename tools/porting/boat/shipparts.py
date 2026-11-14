"""shipparts.py pid : every actor hanging (at any depth) from the vehicle 0xB010000A: key, parent, its TS world block (+0xEC/+0xF8)."""
import struct as _st
with open(r'D:/SteamLibrary/steamapps/common/Crimson Desert/bin64/CrimsonDesert.exe', 'rb') as _f:
    _h = _f.read(0x400)
_ts = _st.unpack_from('<I', _h, _st.unpack_from('<I', _h, 0x3C)[0] + 8)[0]
# The world slot of the installed build: 1.0.0.3663 (PE 0x6AF5D198) or 1.0.0.3576 (0x6AED2E85).
WORLD_SLOT = {0x6AF5D198: 0x72451C0, 0x6AED2E85: 0x71C0100}[_ts]
import sys, collections
sys.path.insert(0, r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/tools/porting')
from live_reader_check import Reader
B = 0x140000000; r = Reader(int(sys.argv[1]))
def rp(a):
    try: return r.ptr(a)
    except Exception: return 0
def ru(a, f):
    try: return r.unpack(a, f)
    except Exception: return None
world = rp(B + WORLD_SLOT); mgr = rp(world + 0x30); t = rp(mgr + 8); n = ru(t + 0x88, '<I')[0]
buckets = rp(t + 0x98); nodes = rp(t + 0xA0); actors = {}
for bi in range(n):
    base = buckets + bi * 0x100; c = ru(base, '<I')
    if not c: continue
    for i in range(min(c[0], 31)):
        k, idx = ru(base + 8 + i * 8, '<II'); node = rp(nodes + idx * 8); a = rp(node + 8) if node else 0
        if a: actors[k] = a
par = {}
for k, a in actors.items():
    comps = rp(a + 0x68); h = rp(comps + 0x1B8) if comps else 0
    if h: par[k] = ru(h + 0x1C, '<I')[0]
kids = collections.defaultdict(list)
for k, p in par.items(): kids[p].append(k)
root = 0xB010000A; todo = [(root, 0)]; seen = []
while todo:
    k, d = todo.pop(); seen.append((k, d))
    for c in sorted(kids.get(k, []), reverse=True): todo.append((c, d + 1))
for k, d in seen:
    a = actors.get(k)
    ts = rp(rp(a + 0x68) + 0x1A0) if a else 0
    w = ru(ts + 0xEC, '<3f') if ts else None; s = ru(ts + 0xF8, '<hh') if ts else None
    inf = rp(a + 0x88); typ = ru(inf + 1, '<B')[0] if inf else None
    wp = f'({w[0] + s[0]*1000:9.1f}, {w[1]:6.1f}, {w[2] + s[1]*1000:8.1f})' if w and s else '-'
    print('  ' * d + f'{k:#010x} t{typ} world {wp}')
