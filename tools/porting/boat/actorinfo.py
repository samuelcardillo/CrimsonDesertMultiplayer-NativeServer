"""actorinfo.py pid key [key ...] : for each actor key (hex) on that copy: present or not, type, controller, hierarchy
parent and attach type, TS local position (+0xB4, sector +0xC0), TS world block (+0xEC, +0xF8) and the scene object.
Read-only (3663)."""
import os
import sys
_HERE = os.path.dirname(os.path.abspath(__file__)).replace('\\', '/')
sys.path.insert(0, r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/tools/porting')
sys.path.insert(0, _HERE + '/../livetest')
from live_reader_check import Reader
from cdbuild import WORLD_SLOT

B = 0x140000000
r = Reader(int(sys.argv[1]))


def rp(a):
    try:
        return r.ptr(a)
    except Exception:
        return 0


def ru(a, f):
    try:
        return r.unpack(a, f)
    except Exception:
        return None


world = rp(B + WORLD_SLOT); mgr = rp(world + 0x30); t = rp(mgr + 8); n = ru(t + 0x88, '<I')[0]
buckets = rp(t + 0x98); nodes = rp(t + 0xA0)
for ks in sys.argv[2:]:
    key = int(ks, 16)
    base = buckets + (key % n) * 0x100
    c = ru(base, '<I')[0]
    a = 0
    for i in range(min(c, 31)):
        k, idx = ru(base + 8 + i * 8, '<II')
        if k == key:
            node = rp(nodes + idx * 8); a = rp(node + 8) if node else 0
    if not a:
        print(f'{key:#010x} NOT in the actor table')
        continue
    comps = rp(a + 0x68); h = rp(comps + 0x1B8) if comps else 0
    par = ru(h + 0x1C, '<I')[0] if h else 0
    att = ru(h + 0x18, '<B')[0] if h else -1
    ts = rp(comps + 0x1A0) if comps else 0
    lp = ru(ts + 0xB4, '<3f') if ts else None; ls = ru(ts + 0xC0, '<hh') if ts else None
    wp = ru(ts + 0xEC, '<3f') if ts else None; ws = ru(ts + 0xF8, '<hh') if ts else None
    inf = rp(a + 0x88); typ = ru(inf + 1, '<B')[0] if inf else -1
    ctl = ru(a + 0x90, '<I')[0]
    sc = rp(comps + 0x30) if comps else 0
    node = rp(sc + 0x18) if sc else 0
    f = lambda p, s: f'({p[0] + s[0] * 1000:.2f}, {p[1]:.2f}, {p[2] + s[1] * 1000:.2f})' if p and s else '-'
    print(f'{key:#010x} actor {a:#x} vt {rp(a) - B:#x} t{typ} ctl {ctl:#010x} parent {par:#010x} att {att} local {f(lp, ls)} '
          f'world {f(wp, ws)} scene comp {sc:#x} node {node:#x}')
