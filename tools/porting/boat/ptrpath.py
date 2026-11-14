"""ptrpath.py pid from_hex to_hex [depth] [span]: pointer paths from an object to another (BFS; a pointer into
[to-0x40, to+0x200) counts). Prints the offsets of each hop."""
import sys, struct, collections
sys.path.insert(0, r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/tools/porting')
from live_reader_check import Reader
r = Reader(int(sys.argv[1])); src, dst = int(sys.argv[2], 16), int(sys.argv[3], 16)
depth = int(sys.argv[4]) if len(sys.argv) > 4 else 4; span = int(sys.argv[5], 16) if len(sys.argv) > 5 else 0x300
def rdq(a, n):
    try: return r.read(a, n)
    except Exception: return None
seen = {src}; q = collections.deque([(src, [])]); hits = 0
while q and hits < 12:
    o, path = q.popleft()
    if len(path) >= depth: continue
    data = rdq(o, span)
    if not data: continue
    for off in range(0, len(data) - 7, 8):
        v = struct.unpack_from('<Q', data, off)[0]
        if not (0x10000000000 <= v < 0x7FFFFFFFFFFF): continue
        if dst - 0x40 <= v < dst + 0x200:
            print('path', [hex(x) for x in path + [off]], f'-> {v:#x} (target{v - dst:+#x})'); hits += 1
            continue
        if v not in seen and len(seen) < 400000:
            seen.add(v); q.append((v, path + [off]))
print('visited', len(seen))
