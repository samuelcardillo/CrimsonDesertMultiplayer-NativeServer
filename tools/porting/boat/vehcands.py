"""vehcands.py pid : every type-7 actor with a vehicle component hanging (attach 7) from another actor: parent, its
vtable and controller, the gimmick's hierarchy children (build 3576, read-only)."""
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
own = ru(rp(mgr + 0x58) + 0x60, '<I')[0]
buckets = rp(t + 0x98); nodes = rp(t + 0xA0)
actors = {}
for bi in range(n):
    base = buckets + bi * 0x100; c = ru(base, '<I')
    if not c: continue
    for i in range(min(c[0], 31)):
        k, idx = ru(base + 8 + i * 8, '<II'); node = rp(nodes + idx * 8); a = rp(node + 8) if node else 0
        if a: actors[k] = a
print('own', hex(own), 'actors', len(actors))
info = {}; hier = {}; children = collections.defaultdict(list)
for k, a in actors.items():
    inf = rp(a + 0x88); typ = ru(inf + 1, '<B')[0] if inf else None
    comps = rp(a + 0x68); h = rp(comps + 0x1B8) if comps else 0
    veh = rp(comps + 0x48) if comps else 0
    pk = None; at = None
    if h:
        at = ru(h + 0x18, '<B')[0]; pk = ru(h + 0x1C, '<I')[0]
        if pk: children[pk].append((k, typ, at))
    info[k] = (a, inf, typ, veh, at, pk)
for k, (a, inf, typ, veh, at, pk) in sorted(info.items()):
    if typ != 7 or not veh or at != 7: continue
    p = info.get(pk)
    ptyp = p[2] if p else None
    vt = rp(p[0]) - B if p else 0
    ctl = ru(p[0] + 0x90, '<I')[0] if p else 0
    raw = r.read(inf, 0x30) if inf else b''
    ch = children.get(k, [])
    v160 = ru(veh + 0x160, '<Q')[0]
    print(f'{k:#010x} parent {pk:#010x} t{ptyp} vt{vt:#x} ctl {ctl:#x}{" OWN" if ctl==own else ""} | children {len(ch)} {[hex(c[0]) for c in ch[:6]]} | veh+160 {v160:#x}')

