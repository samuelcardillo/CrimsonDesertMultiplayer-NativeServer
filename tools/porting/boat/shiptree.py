"""shiptree.py host_pid guest_pid [root_key] : every actor hanging (at any depth) from the vehicle (default 0xB010000A)
on both copies, side by side: type, parent, attach type, local TS position, and which copy has it. Read-only (3663)."""
import collections
import os
import sys
_HERE = os.path.dirname(os.path.abspath(__file__)).replace('\\', '/')
sys.path.insert(0, r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/tools/porting')
sys.path.insert(0, _HERE + '/../livetest')
from live_reader_check import Reader
from cdbuild import WORLD_SLOT

B = 0x140000000
ROOT = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0xB010000A


def tree(pid):
    r = Reader(pid)

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
    buckets = rp(t + 0x98); nodes = rp(t + 0xA0); actors = {}
    for bi in range(n):
        base = buckets + bi * 0x100; c = ru(base, '<I')
        if not c:
            continue
        for i in range(min(c[0], 31)):
            k, idx = ru(base + 8 + i * 8, '<II'); node = rp(nodes + idx * 8); a = rp(node + 8) if node else 0
            if a:
                actors[k] = a
    info = {}
    kids = collections.defaultdict(list)
    for k, a in actors.items():
        comps = rp(a + 0x68); h = rp(comps + 0x1B8) if comps else 0
        par = ru(h + 0x1C, '<I')[0] if h else 0
        att = ru(h + 0x18, '<B')[0] if h else 0
        ts = rp(comps + 0x1A0) if comps else 0
        lp = ru(ts + 0xB4, '<3f') if ts else None
        inf = rp(a + 0x88); typ = ru(inf + 1, '<B')[0] if inf else -1
        info[k] = (typ, par, att, lp)
        if par:
            kids[par].append(k)
    out = {}
    todo = [(ROOT, 0)]
    while todo:
        k, d = todo.pop()
        if k in out:
            continue
        out[k] = (d,) + info.get(k, (-1, 0, 0, None))
        for c in kids.get(k, []):
            todo.append((c, d + 1))
    return out


h = tree(int(sys.argv[1])); g = tree(int(sys.argv[2]))
print(f'host {len(h)} actors, guest {len(g)}')
for k in sorted(set(h) | set(g)):
    a, b = h.get(k), g.get(k)

    def fmt(e):
        if not e:
            return 'MISSING'.ljust(58)
        d, typ, par, att, lp = e
        p = f'({lp[0]:7.2f},{lp[1]:7.2f},{lp[2]:7.2f})' if lp else '-'
        return f'd{d} t{typ} par {par:#010x} att {att:2d} {p}'.ljust(58)
    flag = ''
    if a and b and a[4] and b[4] and max(abs(a[4][i] - b[4][i]) for i in range(3)) > 0.3 and a[2] == b[2]:
        flag = ' DIFF'
    print(f'{k:#010x} host {fmt(a)} | guest {fmt(b)}{flag}')
