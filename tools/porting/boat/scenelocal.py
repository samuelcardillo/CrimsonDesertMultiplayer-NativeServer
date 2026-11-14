"""scenelocal.py host_pid guest_pid key_lo key_hi: for every actor of the key range on both copies: the scene object
([[comps+0x30]+0x18]-0x28), its vtable, link (+0x80) and local transform (+0x1D0: quat +0xC, pos +0x1C), next to the TS local."""
import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__)).replace('\\', '/')
import sys, struct
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
            if not (lo <= k <= hi): continue
            try:
                a = r.ptr(r.ptr(nodes + idx * 8) + 8); comps = r.ptr(a + 0x68); ts = r.ptr(comps + 0x1A0)
                c30 = r.ptr(comps + 0x30); so = r.ptr(c30 + 0x18) - 0x28 if c30 else 0
                tl = r.unpack(ts + 0xB4, '<3f'); tq = r.unpack(ts + 0xA4, '<4f')
                if so > 0x10000:
                    vt = r.unpack(so, '<Q')[0] - B; link = r.ptr(so + 0x80); blk = r.read(so + 0x1D0, 0x2C)
                    sp = struct.unpack_from('<3f', blk, 0x1C); sq = struct.unpack_from('<4f', blk, 0xC)
                    out[k] = (tl, tq, vt, bool(link), sp, sq, r.unpack(c30, '<Q')[0] - B)
                else:
                    out[k] = (tl, tq, 0, False, None, None, 0)
            except Exception as e:
                out[k] = None
    return out
h, g = table(int(sys.argv[1])), table(int(sys.argv[2]))
rf = lambda t: '(' + ','.join(f'{v:6.2f}' for v in t) + ')'
for k in sorted(set(h) | set(g)):
    for nm, x in (('host ', h.get(k)), ('guest', g.get(k))):
        if not x: print(f'{k:#x} {nm} -'); continue
        tl, tq, vt, link, sp, sq, cvt = x
        if sp is None: print(f'{k:#x} {nm} ts {rf(tl)} no scene object'); continue
        same = all(abs(a - b) < 0.02 for a, b in zip(tl, sp))
        print(f'{k:#x} {nm} ts {rf(tl)} scene vt {vt:#x} comp vt {cvt:#x} link {int(link)} local {rf(sp)} q {rf(sq)}{"" if same else "   != ts"}')
