"""Teleport a copy to the nexus at a world point through its map, calibrated with map pins.
usage: map_tp.py pid role tx tz   (role: host | guest; the copy's sniffer log has its pins)
Pins: CreateOrChangePinMarkerReq carries the world x, z of the map point (floats at payload +8, +16). Space over an
icon makes no pin, and Space over a pin removes it: each pin tries a few points around the wanted one.
Map: north up, x to the right; the mouse wheel zooms around the screen centre."""
import glob, os, struct, subprocess, sys, time

SP = os.path.dirname(os.path.abspath(__file__))
BIN = r'D:/SteamLibrary/steamapps/common/Crimson Desert/bin64'
pid, role, tx, tz = int(sys.argv[1]), sys.argv[2], float(sys.argv[3]), float(sys.argv[4])
CX, CY = 1916, 1078


def ui(*a):
    return subprocess.run(['pwsh', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', os.path.join(SP, 'ui.ps1'),
                           '-GamePid', str(pid), *a], capture_output=True, text=True).stdout


def packets_log():
    return max(glob.glob(os.path.join(BIN, f'cdmp_packets.{role}_*.log')), key=os.path.getmtime)


def pins():
    with open(packets_log(), 'rb') as f:
        f.seek(0, 2)
        f.seek(max(0, f.tell() - 6_000_000))
        return [l for l in f.read().split(b'\n') if b'CreateOrChangePinMarkerReq ' in l and b'stats' not in l]


def decode(line):
    b = bytes(int(h, 16) for h in line.split(b'|')[1].split())
    return struct.unpack_from('<f', b, 8)[0], struct.unpack_from('<f', b, 16)[0]


def last_line(tag):
    """The last line of the packets log with `tag` (each line starts with its own time, so a new one differs)."""
    with open(packets_log(), 'rb') as f:
        f.seek(0, 2)
        f.seek(max(0, f.tell() - 6_000_000))
        found = None
        for l in f.read().split(bytes([10])):
            if tag in l and b'stats' not in l: found = l
        return found


def pin(x, y):
    # A pin is read from a NEW last CreateOrChangePinMarkerReq line, never from a count of lines: the 6 MB window of a
    # growing log drops old lines, so counts change by themselves (7-nov: two calibration pins read as one, scale 0).
    for ox, oy in ((0, 0), (55, 35), (-55, 35), (55, -35), (-55, -35), (110, 0), (-110, 0), (0, 90)):
        px, py = x + ox, y + oy
        # A click moves the map's own cursor (a cursor move alone did not, on the guest's copy, 7-nov 17:55).
        ui('-Do', 'click', '-X', str(px), '-Y', str(py))
        # Space over an old pin removes it (RemovePinMarkerReq); a second Space then puts a new one there.
        for press in range(2):
            p0, r0 = last_line(b'CreateOrChangePinMarkerReq '), last_line(b'RemovePinMarkerReq ')
            ui('-Do', 'key', '-Keys', 'SPACE', '-HoldMs', '100')
            removed = False
            for _ in range(6):
                time.sleep(0.4)
                p = last_line(b'CreateOrChangePinMarkerReq ')
                if p is not None and p != p0:
                    wx, wz = decode(p)
                    return wx, wz, px, py
                r = last_line(b'RemovePinMarkerReq ')
                if r is not None and r != r0:
                    removed = True
                    break
            if not removed:
                break
    raise SystemExit(f'no pin near ({x},{y})')


def calibrate(step):
    for st in (step, step + 200, step - 150):
        a = pin(CX, CY)
        b = pin(CX - st, CY)
        if a[2] == b[2]:
            continue
        scale = (a[0] - b[0]) / float(a[2] - b[2])
        if scale > 0.01:
            return (a[0] + (CX - a[2]) * scale, a[1] - (CY - a[3]) * scale), scale
        print('calibration gave scale', scale, ': again')
    raise SystemExit('calibration failed')


def center(scale):
    a = pin(CX, CY)
    return a[0] + (CX - a[2]) * scale, a[1] - (CY - a[3]) * scale


def target_px(c, scale):
    return CX + (tx - c[0]) / scale, CY - (tz - c[1]) / scale


def map_open():
    """The map's parchment covers half the screen or more (0.5-0.69 on maps, at most 0.04 in the world, 7-nov); the old
    test of the key-hint bar's brightness failed over a coast (dark sea under the bar, Vellua Village)."""
    shot = os.path.join(SP, 'shops', f'mt_open_{role}.png')
    ui('-Do', 'shot', '-Out', shot)
    from PIL import Image
    im = Image.open(shot).convert('RGB').resize((220, 124))
    n = sum(1 for r, g, b in im.getdata()
            if 180 <= r <= 240 and 175 <= g <= 235 and 160 <= b <= 230 and abs(r - g) < 18 and r - b < 35 and r >= b)
    return n / (220 * 124) > 0.12  # 13-nov: a map centred on the sea shows ~0.15 parchment


for attempt in range(3):
    # The copy in the background drops a key pressed while it is brought to the front: front it first.
    ui('-Do', 'look', '-Dx', '0', '-Dy', '0', '-Steps', '1'); time.sleep(1.5)
    ui('-Do', 'key', '-Keys', 'M', '-HoldMs', '150'); time.sleep(4)
    if map_open():
        break
    print('map not open, pressing M again')
else:
    raise SystemExit('the map does not open')
ui('-Do', 'wheel', '-X', str(CX), '-Y', str(CY), '-Dy', '-120', '-Steps', '8'); time.sleep(2)
c, scale = calibrate(800)
print('center', [round(v) for v in c], 'scale m/px', round(scale, 3))
ratio = 1.2  # map px per mouse px when dragging; measured below
for _ in range(8):
    px, py = target_px(c, scale)
    print('target px', round(px), round(py))
    if abs(px - CX) < 250 and abs(py - CY) < 250:
        break
    want_x, want_y = CX - px, CY - py
    dx = max(-1400, min(1400, want_x / ratio))
    dy = max(-700, min(700, want_y / ratio))
    ui('-Do', 'drag', '-X', str(CX), '-Y', str(CY), '-Dx', str(int(dx)), '-Dy', str(int(dy)), '-Steps', '40')
    time.sleep(1.5)
    c2 = center(scale)
    moved = ((c[0] - c2[0]) / scale, (c2[1] - c[1]) / scale)  # map px the content moved
    if abs(dx) > 100 and abs(moved[0]) > 50:
        ratio = max(0.5, min(4.0, moved[0] / dx))
    elif abs(dy) > 100 and abs(moved[1]) > 50:
        ratio = max(0.5, min(4.0, moved[1] / dy))
    c = c2
    print('center now', [round(v) for v in c], 'drag ratio', round(ratio, 2))
else:
    raise SystemExit('target not brought to the centre')
ui('-Do', 'wheel', '-X', str(CX), '-Y', str(CY), '-Dy', '120', '-Steps', '5'); time.sleep(2)
c, scale = calibrate(400)
px, py = target_px(c, scale)
print('zoomed: center', [round(v) for v in c], 'scale', round(scale, 3), 'target px', round(px), round(py))
shot = os.path.join(SP, 'shops', f'mt_{role}.png')
ui('-Do', 'shot', '-Out', shot)
gx, gy = int(px * 1100 / 3840), int(py * 1100 / 3840)
r = subprocess.run(['bash', os.path.join(SP, 'tp.sh'), str(pid), shot.replace(os.sep, '/'), str(gx), str(gy)],
                   capture_output=True, text=True, cwd=SP)
print(r.stdout.strip()[-300:], r.stderr.strip()[-200:])
sys.exit(0 if 'SPACE' in r.stdout else 1)
