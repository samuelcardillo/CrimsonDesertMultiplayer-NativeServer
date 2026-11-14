"""poke3f.py pid addr_hex x y z : TEST WRITE of three floats into a copy's memory (prints before/after)."""
import sys, struct, ctypes
sys.path.insert(0, r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/tools/porting')
from live_reader_check import Reader
pid, addr = int(sys.argv[1]), int(sys.argv[2], 16); v = [float(a) for a in sys.argv[3:6]]
r = Reader(pid); print('before', [round(x, 3) for x in r.unpack(addr, '<3f')])
k32 = ctypes.WinDLL('kernel32', use_last_error=True); h = k32.OpenProcess(0x0020 | 0x0008 | 0x0010, False, pid)
n = ctypes.c_size_t(); data = struct.pack('<3f', *v)
ok = k32.WriteProcessMemory(ctypes.c_void_p(h), ctypes.c_void_p(addr), data, len(data), ctypes.byref(n))
print('write', bool(ok), n.value, 'after', [round(x, 3) for x in r.unpack(addr, '<3f')]); k32.CloseHandle(h)
