"""parents.py capture.bin key_hex: the parents named by that actor's MoveActorReq (2790) and MoveActorAck (3008), by direction."""
import mmap, struct, sys, re, collections
f = open(sys.argv[1], 'rb'); m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
k = struct.pack('<I', int(sys.argv[2], 16))
for op, nm, size in ((2790, 'MoveActorReq', 518), (3008, 'MoveActorAck', 239)):
    pat = re.compile(re.escape(struct.pack('<H', op)) + b'...' + re.escape(k), re.S)
    c = collections.Counter()
    for mt in pat.finditer(m):
        o = mt.start(); t, d, _, sz, copied = struct.unpack_from('<QBBHH', m, o - 24)
        if copied < 5 + 76: continue
        pl = m[o + 5: o + 5 + 76]
        c[(d, struct.unpack_from('<Q', pl, 68)[0])] += 1
    print(nm, {f'dir {d} parent {p:#x}': n for (d, p), n in sorted(c.items(), key=lambda x: -x[1])[:8]})
