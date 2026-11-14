"""scenechain.py pid sceneobj_hex: walk a scene object's attach chain (+0x80 -> +8 parent): vtable, inherit flags
(+0x1A4..6), the transform at +0x1D0 (scale 3f, quat 4f, pos 3f, sector 2h) and the link's fields."""
import sys, struct
sys.path.insert(0, r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/tools/porting')
from live_reader_check import Reader
B = 0x140000000; r = Reader(int(sys.argv[1])); o = int(sys.argv[2], 16)
for depth in range(8):
    vt = r.unpack(o, '<Q')[0]; link = r.ptr(o + 0x80)
    blk = r.read(o + 0x1D0, 0x2C); sc = struct.unpack_from('<3f', blk, 0); q = struct.unpack_from('<4f', blk, 0xC); p = struct.unpack_from('<3f', blk, 0x1C); s = struct.unpack_from('<2h', blk, 0x28)
    fl = r.unpack(o + 0x1A4, '<3B')
    print(f'[{depth}] obj {o:#x} vt exe+{vt - B:#x} inherit {fl} +0xFC {r.unpack(o + 0xFC, "<2B")}')
    print(f'      xform +0x1D0: scale {tuple(round(v, 3) for v in sc)} q {tuple(round(v, 3) for v in q)} pos {tuple(round(v, 3) for v in p)} sector {s}')
    if not link:
        print('      no link (+0x80 null)'); break
    lb = r.read(link, 0x40)
    par = struct.unpack_from('<Q', lb, 8)[0]
    print(f'      link {link:#x}: ' + ' '.join(f'{struct.unpack_from("<Q", lb, i)[0]:#x}' for i in range(0, 0x40, 8)))
    if not par:
        print('      link parent null'); break
    print(f'      parent {par:#x} byte+0x15 {r.unpack(par + 0x15, "<B")[0]}')
    o = par
