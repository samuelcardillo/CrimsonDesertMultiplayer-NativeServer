"""weatherdump.py pid [pid2] : the scene weather system X and its holder blocks A/B/C as raw floats (build 3663).
With two pids, prints only the words that differ (by more than 1e-3, or as raw words when not floats).
X = [[[exe+0x72451C8]+0x48]+0x38]; holder = [X+0x60]; A/B/C = [holder+0x20/+0x28/+0x30] (weather_sync_logic.h kGame3663).
Read-only."""
import struct
import sys
sys.path.insert(0, r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/tools/porting')
from live_reader_check import Reader

B = 0x140000000
RANGES = {'A': (0x100, 0x1C0), 'B': (0x28, 0x130), 'C': (0xE0, 0x200), 'X': (0x28, 0x180)}


def blocks(pid):
    r = Reader(pid)
    x = r.ptr(r.ptr(r.ptr(B + 0x72451C8) + 0x48) + 0x38)
    h = r.ptr(x + 0x60)
    out = {'X': x, 'A': r.ptr(h + 0x20), 'B': r.ptr(h + 0x28), 'C': r.ptr(h + 0x30)}
    data = {}
    for name, base in out.items():
        lo, hi = RANGES[name]
        data[name] = r.read(base + lo, hi - lo)
    return data


def words(buf):
    return [(struct.unpack_from('<I', buf, i)[0], struct.unpack_from('<f', buf, i)[0]) for i in range(0, len(buf) - 3, 4)]


def show(u, f):
    return f'{f:.4f}' if (abs(f) > 1e-6 and abs(f) < 1e7) or u == 0 else f'{u:08X}'


d = [blocks(int(p)) for p in sys.argv[1:3]]
for name in ('A', 'B', 'C', 'X'):
    lo, hi = RANGES[name]
    w0 = words(d[0][name])
    w1 = words(d[1][name]) if len(d) > 1 else None
    line = []
    for i, (u, f) in enumerate(w0):
        off = lo + i * 4
        if w1 is None:
            line.append(f'+{off:X}={show(u, f)}')
        else:
            u2, f2 = w1[i]
            isf = lambda uu, ff: (abs(ff) > 1e-6 and abs(ff) < 1e7) or uu == 0
            if u != u2 and not (isf(u, f) and isf(u2, f2) and abs(f - f2) <= 1e-3 * max(1.0, abs(f))):
                line.append(f'+{off:X}: {show(u, f)} | {show(u2, f2)}')
    print(name, ' '.join(line) if w1 is None else ('; '.join(line) or 'same'))
