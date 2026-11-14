"""vfreplay.py : replay the guest's received vehicle samples (0xB010000A acks, arrival QPC) through vfl::Track's logic
(Python port) for several delays; compare with the host ship's true path (host client's 0xB0101AF0 reqs) at T - d_char."""
import mmap, re, struct, math, bisect
B = 'D:/SteamLibrary/steamapps/common/Crimson Desert/bin64/'
def load(path, key, op, d_want):
    f = open(path, 'rb'); m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ); k = struct.pack('<I', key); out = []
    for mt in re.finditer(re.escape(struct.pack('<H', op)) + b'...' + re.escape(k), m):
        o = mt.start(); t, d, _, size, copied = struct.unpack_from('<QBBHH', m, o - 24)
        if d != d_want or copied < 200 or copied > 600: continue
        x, y, z = struct.unpack_from('<3f', m, o + 5 + 196)
        out.append((t / 1e6, x, z))
    return out
import glob, os
G = sorted(glob.glob(B + 'cdmp_packets.guest_20261113-1338*.bin'))[-1]
H = sorted(glob.glob(B + 'cdmp_packets.host_20261113-1249*.bin'))[-1]
acks = load(G, 0xB010000A, 3094, 2)
truth = load(H, 0xB010000A, 2833, 1)
print(os.path.basename(G), len(acks), 'acks;', os.path.basename(H), len(truth), 'ship reqs')
# the sailing window: where the true ship moved faster than 2 m/s
moving = [(a, b) for a, b in zip(truth, truth[1:]) if b[0] > a[0] + 0.2 and 2 < math.hypot(b[1] - a[1], b[2] - a[2]) / (b[0] - a[0]) < 15]
t_lo, t_hi = moving[0][0][0] - 5, moving[-1][1][0] + 5
print(f'moving segments {len(moving)}, span {t_hi - t_lo:.0f} s, max true speed {max(math.hypot(b[1]-a[1], b[2]-a[2])/(b[0]-a[0]) for a, b in moving):.1f} m/s')
tt = [p[0] for p in truth]
def true_at(t):
    i = bisect.bisect_left(tt, t)
    if i <= 0: return truth[0][1:]
    if i >= len(truth): return truth[-1][1:]
    a, b = truth[i - 1], truth[i]; f = (t - a[0]) / (b[0] - a[0]) if b[0] > a[0] else 0
    return (a[1] + (b[1] - a[1]) * f, a[2] + (b[2] - a[2]) * f)
def drawn(samples, now, delay, max_ex=1.0, tele=60.0):
    s = [p for p in samples if p[0] <= now]
    if not s: return None
    t = now - delay
    if len(s) == 1 or t <= s[0][0]: return s[0][1:] if (len(s) == 1 or t <= s[0][0]) else s[-1][1:]
    for a, b in zip(s, s[1:]):
        if a[0] <= t <= b[0]:
            if math.hypot(b[1] - a[1], b[2] - a[2]) > tele: return b[1:]
            f = (t - a[0]) / (b[0] - a[0]); return (a[1] + (b[1] - a[1]) * f, a[2] + (b[2] - a[2]) * f)
    a, b = s[-2], s[-1]; over = t - b[0]
    if over > max_ex or math.hypot(b[1] - a[1], b[2] - a[2]) > tele: return b[1:]
    k = over / (b[0] - a[0]); return (b[1] + (b[1] - a[1]) * k, b[2] + (b[2] - a[2]) * k)
win = [p for p in acks if t_lo - 10 <= p[0] <= t_hi + 10]
# drop consecutive identical samples (the Track does)
ded = []
for p in win:
    if not ded or (abs(p[1] - ded[-1][1]) > 1e-3 or abs(p[2] - ded[-1][2]) > 1e-3): ded.append(p)
ints = [b[0] - a[0] for a, b in zip(ded, ded[1:])]
print(f'samples in the window {len(ded)}, interval median {sorted(ints)[len(ints)//2]:.2f} s max {max(ints):.2f} s')
for delay in (0.3, 0.6, 1.2):
    for d_char in (0.2, 0.3, 0.45):
        al, lag = [], []
        T = t_lo
        while T <= t_hi:
            if not any(a[0] - 1 <= T <= b[0] + 1 for a, b in moving): T += 0.05; continue
            p = drawn(ded, T, delay)
            if p:
                tc = true_at(T - d_char); al.append(math.hypot(p[0] - tc[0], p[1] - tc[1]))
            T += 0.05
        s = sorted(al)
        print(f'delay {delay*1000:.0f} ms: ship vs helmsman (drawn {d_char*1000:.0f} ms late) median {s[len(s)//2]:.2f} p90 {s[int(len(s)*.9)]:.2f} max {s[-1]:.2f} m')
