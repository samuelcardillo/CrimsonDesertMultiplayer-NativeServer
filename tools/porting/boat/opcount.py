"""opcount.py capture.bin t_from t_to [ops,comma] : per (dir, op) counts in a window; with ops, the keys at payload+0 for them."""
import mmap, re, struct, sys, collections
f = open(sys.argv[1], 'rb'); m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
t0 = struct.unpack_from('<Q', m, 12)[0]; ta, tb = float(sys.argv[2]), float(sys.argv[3])
want = set(int(x) for x in sys.argv[4].split(',')) if len(sys.argv) > 4 else set()
names = {}
for line in open('D:/SteamLibrary/steamapps/common/Crimson Desert/multi/src/common/native_opcode_table.inc'):
    mm = re.match(r'\s*\{(\d+), (\d+), \d+U, "(\w+)"\}', line)
    if mm: names[int(mm.group(2))] = mm.group(3)
pos = 12
for mt in re.finditer(b'\x11\x0b\x00\x06\x02', m):
    t = struct.unpack_from('<Q', m, mt.start() - 24)[0]
    if (t - t0) / 1e6 >= ta: pos = mt.start() - 24; break
cnt = collections.Counter(); keys = collections.Counter()
while pos + 24 <= len(m):
    t, d, _, size, copied = struct.unpack_from('<QBBHH', m, pos)
    if (t - t0) / 1e6 > tb: break
    pkt = m[pos + 24: pos + 24 + copied]; pos += 24 + copied
    if len(pkt) < 5: continue
    op = struct.unpack_from('<H', pkt, 0)[0]; cnt[(d, op)] += 1
    if op in want and len(pkt) >= 9: keys[(d, op, hex(struct.unpack_from('<I', pkt, 5)[0]))] += 1
for (d, op), v in sorted(cnt.items(), key=lambda x: -x[1])[:45]: print(v, d, op, names.get(op, '?'))
for k, v in keys.most_common(30): print(' ', v, k)
