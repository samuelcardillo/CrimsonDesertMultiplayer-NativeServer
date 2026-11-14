"""keyscan.py capture.bin key_hex [t_from t_to] [maxdump]: every message whose payload has the key (u32 LE), by dir/op and
offset of the key; walks all records from the start. Names from the sibling .log."""
import mmap, re, struct, sys, collections
path, key = sys.argv[1], int(sys.argv[2], 16)
ta = float(sys.argv[3]) if len(sys.argv) > 3 else 0.0
tb = float(sys.argv[4]) if len(sys.argv) > 4 else 1e12
maxdump = int(sys.argv[5]) if len(sys.argv) > 5 else 0
names = {}
try:
    with open(path[:-4] + '.log', 'rb') as lf:
        for i, line in enumerate(lf):
            if i > 400000: break
            mm = re.match(rb'\s*[\d.]+ \S+ (\S+)\s+(\d+) slot', line)
            if mm: names[int(mm.group(2))] = mm.group(1).decode()
except Exception as e:
    print(e)
f = open(path, 'rb'); m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
t0 = struct.unpack_from('<Q', m, 12)[0]; k = struct.pack('<I', key)
pos = 12; cnt = collections.Counter(); first = {}; dumped = 0
while pos + 24 <= len(m):
    t, d, _, size, copied = struct.unpack_from('<QBBHH', m, pos)
    s = (t - t0) / 1e6
    pkt = m[pos + 24: pos + 24 + copied]; pos += 24 + copied
    if s < ta or len(pkt) < 5: continue
    if s > tb: break
    op = struct.unpack_from('<H', pkt, 0)[0]
    i = pkt.find(k, 5)
    if i < 0: continue
    kk = (d, op, names.get(op, '?'), i - 5, size)
    cnt[kk] += 1
    if kk not in first:
        first[kk] = (round(s, 3), pkt[5:5 + 96].hex(' '))
    if dumped < maxdump and names.get(op, '?') not in ('MoveActorAck', 'MoveActorReq'):
        dumped += 1
        print(f'--- t {s:.3f} dir {d} op {op} {names.get(op, "?")} size {size} key at +{i - 5}\n{pkt[5:].hex(" ")[:3000]}')
for kk, v in sorted(cnt.items(), key=lambda x: first[x[0]][0]): print(first[kk][0], v, kk)
