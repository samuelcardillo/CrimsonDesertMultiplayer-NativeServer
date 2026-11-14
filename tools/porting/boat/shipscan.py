"""shipscan.py capture.bin key_hex [start_gb] [end_gb] : fast regex scan of MoveActorReq(2833)/Ack(2697) frames of one actor.
Prints per-second rows: t, dir, op, world pos(+196), local pos(+4), parent(+68), stamp(+212)."""
import mmap, re, struct, sys, collections
path, key = sys.argv[1], int(sys.argv[2], 16)
a = int(float(sys.argv[3]) * 2**30) if len(sys.argv) > 3 else 0
f = open(path, 'rb'); m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
b = int(float(sys.argv[4]) * 2**30) if len(sys.argv) > 4 else len(m)
t0 = struct.unpack_from('<Q', m, 12)[0]
k = struct.pack('<I', key)
pat = re.compile(re.escape(b'\x11\x0b') + b'...' + re.escape(k) + b'|' + re.escape(b'\x16\x0c') + b'...' + re.escape(k), re.S)
rows = []; cnt = collections.Counter()
for mt in pat.finditer(m, a, b):
    o = mt.start()
    if o < 24: continue
    t, d, _, size, copied = struct.unpack_from('<QBBHH', m, o - 24)
    if copied < 9 or copied > 4096: continue
    op = struct.unpack_from('<H', m, o)[0]
    p = o + 5; n = copied - 5
    cnt[(d, op, n)] += 1
    if n < 220: continue
    wp = struct.unpack_from('<3f', m, p + 196); lp = struct.unpack_from('<3f', m, p + 4)
    par = struct.unpack_from('<Q', m, p + 68)[0]; st = struct.unpack_from('<I', m, p + 212)[0]
    rows.append(((t - t0) / 1e6, d, op, n, wp, lp, par, st))
print('counts (dir, op, payload):', dict(cnt))
last = {}
for r in rows:
    s = int(r[0]); kk = (r[1], r[2])
    if last.get(kk) == s: continue
    last[kk] = s
    print(f'{r[0]:9.2f} d{r[1]} op{r[2]} n{r[3]} world {[round(v,1) for v in r[4]]} local {[round(v,2) for v in r[5]]} parent {r[6]:#x} st {r[7]}')
