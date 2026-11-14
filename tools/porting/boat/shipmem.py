"""shipmem.py pid key_hex : read-only dump of one client actor's TransformSync on 3576."""
import sys, struct
R = r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/'
sys.path.insert(0, R + 'tools/porting')
from live_reader_check import Reader
BASE = 0x140000000
r = Reader(int(sys.argv[1])); key = int(sys.argv[2], 16)
world = r.ptr(BASE + 0x71C0100); mgr = r.ptr(world + 0x30); t = r.ptr(mgr + 8); n = r.unpack(t + 0x88, '<I')[0]
b = r.ptr(t + 0x98) + (key % n) * 0x100; c = r.unpack(b, '<I')[0]; actor = None
for i in range(min(c, 31)):
    k, idx = r.unpack(b + 8 + i * 8, '<II')
    if k == key: actor = r.ptr(r.ptr(r.ptr(t + 0xA0) + idx * 8) + 8)
print('actor', hex(actor or 0))
if actor:
    comps = r.ptr(actor + 0x68); ts = r.ptr(comps + 0x1A0)
    print('ctl +0x90', hex(r.unpack(actor + 0x90, '<I')[0]), 'type', r.unpack(r.ptr(actor + 0x88) + 1, '<B')[0], 'comps', hex(comps), 'ts', hex(ts))
    raw = r.read(ts, 0x900)
    for off in range(0, 0x900, 0x10):
        fl = struct.unpack_from('<4f', raw, off); u = struct.unpack_from('<4I', raw, off)
        txt = ' '.join(f'{v:12.3f}' if abs(v) < 1e6 and (abs(v) > 1e-4 or v == 0) else f'{u[j]:#12x}' for j, v in enumerate(fl))
        print(f'+{off:03x}: {txt}')
