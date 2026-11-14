"""posnow.py pid : the copy's own character position right now (TS +0xB4/+0xC0), and its hierarchy parent key."""
import os as _os
_HERE = _os.path.dirname(_os.path.abspath(__file__)).replace('\\', '/')
import sys
sys.path.insert(0, _HERE)
sys.path.insert(0, r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/tools/porting')
from cdbuild import WORLD_SLOT
from live_reader_check import Reader
B = 0x140000000; r = Reader(int(sys.argv[1]))
world = r.ptr(B + WORLD_SLOT); mgr = r.ptr(world + 0x30); a = r.ptr(mgr + 0x50)
comps = r.ptr(a + 0x68); ts = r.ptr(comps + 0x1A0)
x, y, z = r.unpack(ts + 0xB4, '<fff'); sx, sz = r.unpack(ts + 0xC0, '<hh')
wx, wy, wz = r.unpack(ts + 0xEC, '<fff'); wsx, wsz = r.unpack(ts + 0xF8, '<hh')
h = r.ptr(comps + 0x1B8); par = r.unpack(h + 0x1C, '<I')[0] if h else 0
print(f'{x + sx*1000:.2f} {y:.2f} {z + sz*1000:.2f} world {wx + wsx*1000:.2f} {wy:.2f} {wz + wsz*1000:.2f} parent {par:#x}')
