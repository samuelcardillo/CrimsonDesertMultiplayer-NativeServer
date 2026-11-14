"""keyops.py capture.bin key_hex t_from t_to : every op whose payload mentions key (u32 LE), per dir, between capture seconds.
Starts walking at the first ship MoveActorReq (2833) record after t_from (record aligned)."""
import mmap, re, struct, sys, collections
sys.path.insert(0, 'D:/SteamLibrary/steamapps/common/Crimson Desert/multi/tools/porting')
path, key, ta, tb = sys.argv[1], int(sys.argv[2], 16), float(sys.argv[3]), float(sys.argv[4])
f = open(path, 'rb'); m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
t0 = struct.unpack_from('<Q', m, 12)[0]; k = struct.pack('<I', key)
pat = re.compile(re.escape(b'\x11\x0b') + b'...' + re.escape(k), re.S)
start = None
for mt in pat.finditer(m):
    t = struct.unpack_from('<Q', m, mt.start() - 24)[0]
    if (t - t0) / 1e6 >= ta: start = mt.start() - 24; break
pos = start; cnt = collections.Counter(); first = {}
names = {}
try:
    for line in open('D:/SteamLibrary/steamapps/common/Crimson Desert/multi/src/common/native_opcode_table.inc'):
        mm = re.match(r'\s*\{(\d+), (\d+), \d+U, "(\w+)"\}', line)
        if mm: names[int(mm.group(2))] = mm.group(3)
except Exception as e: print(e)
while pos + 24 <= len(m):
    t, d, _, size, copied = struct.unpack_from('<QBBHH', m, pos)
    s = (t - t0) / 1e6
    if s > tb: break
    pkt = m[pos + 24: pos + 24 + copied]; pos += 24 + copied
    if len(pkt) < 5: continue
    op = struct.unpack_from('<H', pkt, 0)[0]
    i = pkt.find(k, 5)
    if i < 0: continue
    cnt[(d, op, names.get(op, '?'), i - 5)] += 1
    first.setdefault((d, op), (round(s, 2), pkt[:80].hex(' ')))
for kk, v in sorted(cnt.items(), key=lambda x: -x[1]): print(v, kk)
print()
for kk, v in first.items(): print(kk, v)
