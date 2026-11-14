"""dumpobj.py pid addr_hex size_hex : read-only dump as floats/ints/pointers with RTTI names for pointers."""
import sys, json, struct
R = r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/'
sys.path.insert(0, R + 'tools/porting')
from live_reader_check import Reader
BASE = 0x140000000
rt = json.load(open(R + 'tools/porting/data/rtti_3576.json'))
names = {int(v['rva'], 0): c['name'] for c in rt['classes'].values() for v in c['vtables']}
r = Reader(int(sys.argv[1])); a = int(sys.argv[2], 16); n = int(sys.argv[3], 16)
raw = r.read(a, n)
for off in range(0, n, 8):
    q = struct.unpack_from('<Q', raw, off)[0]; f = struct.unpack_from('<2f', raw, off); u = struct.unpack_from('<2I', raw, off)
    note = ''
    if 0x140000000 <= q < 0x14C000000: note = 'exe+' + hex(q - BASE) + (' ' + names[q - BASE] if q - BASE in names else '')
    elif 0x10000000000 < q < 0x7fffffffffff:
        try:
            vt = r.ptr(q); note = 'ptr -> ' + (names.get(vt - BASE, '') if vt else '')
        except Exception: note = 'ptr'
    fs = ' '.join(f'{v:10.3f}' if 1e-4 < abs(v) < 1e6 or v == 0 else f'{u[i]:#10x}' for i, v in enumerate(f))
    print(f'+{off:#05x}: {q:#018x} | {fs} {note}')
