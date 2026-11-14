"""ackdump.py capture.bin key_hex: one MoveActorAck (3008) of the key with a parent and one without, field by field."""
import mmap, struct, sys, re
f = open(sys.argv[1], 'rb'); m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
k = struct.pack('<I', int(sys.argv[2], 16)); pat = re.compile(re.escape(struct.pack('<H', 3008)) + b'...' + re.escape(k), re.S)
with_p = without = None
hits = [mt.start() for mt in pat.finditer(m)]
for o in hits:
    pl = bytes(m[o + 5: o + 5 + 239])
    if len(pl) < 239: continue
    par = struct.unpack_from('<Q', pl, 68)[0]
    if par == 0xFFFFFFFFFFFFFFFF: without = pl
    elif (par >> 28) == 0xB and with_p is None and o > hits[len(hits) // 2]: with_p = pl
for nm, pl in (('WITH parent', with_p), ('WITHOUT parent (last)', without)):
    if not pl: print(nm, 'none'); continue
    f3 = lambda o: [round(v, 3) for v in struct.unpack_from('<3f', pl, o)]; f4 = lambda o: [round(v, 3) for v in struct.unpack_from('<4f', pl, o)]
    print(nm)
    print('  +0 key', hex(struct.unpack_from('<I', pl, 0)[0]), '| local pos +4', f3(4), 'quat +16', f4(16), 'scale +32', f3(32))
    print('  +44..+68', pl[44:68].hex(' '))
    print('  parent +68', hex(struct.unpack_from('<Q', pl, 68)[0]), '| world pos +76', f3(76), 'quat +88', f4(88), 'scale +104', f3(104))
    print('  +116..+140', [round(v, 3) for v in struct.unpack_from('<6f', pl, 116)], '| +140..+180', pl[140:180].hex(' '))
    print('  quat +180', f4(180), 'pos +196', f3(196), 'aux +208', pl[208:212].hex(' '), 'ts +212', struct.unpack_from('<Q', pl, 212)[0], 'tail', pl[220:239].hex(' '))
