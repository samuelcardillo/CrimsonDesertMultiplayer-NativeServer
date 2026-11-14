"""tsprobe.py pid key_hex [seconds]: an actor's TransformSync: local pose, parent frame, network pose, and the pending
request types seen at TS+0x5BC while polling."""
import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__)).replace('\\', '/')
import sys, time, collections
sys.path.insert(0, _HERE + '/../livetest')
sys.path.insert(0, r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/tools/porting')
from cdbuild import WORLD_SLOT
from live_reader_check import Reader
B = 0x140000000; r = Reader(int(sys.argv[1])); key = int(sys.argv[2], 16); secs = float(sys.argv[3]) if len(sys.argv) > 3 else 2.0
world = r.ptr(B + WORLD_SLOT); mgr = r.ptr(world + 0x30); t = r.ptr(mgr + 8); n = r.unpack(t + 0x88, '<I')[0]
b = r.ptr(t + 0x98) + (key % n) * 0x100; c = r.unpack(b, '<I')[0]; a = 0
for i in range(min(c, 31)):
    k, idx = r.unpack(b + 8 + i * 8, '<II')
    if k == key: a = r.ptr(r.ptr(r.ptr(t + 0xA0) + idx * 8) + 8)
comps = r.ptr(a + 0x68); ts = r.ptr(comps + 0x1A0)
f3 = lambda o: tuple(round(v, 3) for v in r.unpack(ts + o, '<3f'))
f4 = lambda o: tuple(round(v, 3) for v in r.unpack(ts + o, '<4f'))
print(f'actor {a:#x} ts {ts:#x} vt {r.unpack(a, "<Q")[0] - B:#x} ts vt {r.unpack(ts, "<Q")[0] - B:#x}')
print('local   +0xB4', f3(0xB4), 'sector', r.unpack(ts + 0xC0, '<hh'), 'q +0xA4', f4(0xA4))
print('frame   +0xEC', f3(0xEC), 'sector', r.unpack(ts + 0xF8, '<hh'), 'q +0xDC', f4(0xDC))
print('net     +0x550', f3(0x550), 'q +0x55C', f4(0x55C))
print('request +0x5AC', f3(0x5AC), 'sector', r.unpack(ts + 0x5B8, '<hh'), 'type', r.unpack(ts + 0x5BC, '<B')[0], 'flags', r.unpack(ts + 0x5BD, '<BB'))
cnt = collections.Counter(); t0 = time.time(); loc = collections.Counter()
while time.time() - t0 < secs:
    cnt[r.unpack(ts + 0x5BC, '<B')[0]] += 1
    loc[f3(0xB4)] += 1
print('types seen at +0x5BC:', dict(cnt)); print('distinct local values:', len(loc), list(loc.items())[:4])
