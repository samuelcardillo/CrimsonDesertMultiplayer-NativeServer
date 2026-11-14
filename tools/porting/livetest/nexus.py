"""Find the bright-blue nexus icon nearest to a guessed PNG point; print click coordinates. usage: nexus.py png x y
The blue pixels around the guess are grouped into blobs and the blob nearest to the guess wins. Taking the centre of
ALL of them (as before 14-nov) failed with the other player standing in town: their blue dot on the map, 25 px from the
nexus, pulled the click off the icon and the teleport dialog never opened."""
import sys
from PIL import Image
im = Image.open(sys.argv[1]).convert('RGB')
gx, gy = int(sys.argv[2]), int(sys.argv[3])
blue = set()
for y in range(max(0, gy - 50), min(im.height, gy + 50)):
    for x in range(max(0, gx - 60), min(im.width, gx + 60)):
        r, g, b = im.getpixel((x, y))
        if b > 200 and g > 150 and r < 140:
            blue.add((x, y))
if not blue:
    print('none'); sys.exit(1)
blobs = []
left = set(blue)
while left:
    seed = left.pop(); stack = [seed]; blob = [seed]
    while stack:
        x, y = stack.pop()
        for dx in (-2, -1, 0, 1, 2):
            for dy in (-2, -1, 0, 1, 2):
                p = (x + dx, y + dy)
                if p in left:
                    left.discard(p); stack.append(p); blob.append(p)
    blobs.append(blob)
big = [b for b in blobs if len(b) >= 6] or blobs


def centre(b):
    return sum(p[0] for p in b) / len(b), sum(p[1] for p in b) / len(b)


best = min(big, key=lambda b: (centre(b)[0] - gx) ** 2 + (centre(b)[1] - gy) ** 2)
cx, cy = centre(best)
s = 3840 / im.width
print(f'png {cx:.1f},{cy:.1f} n {len(best)} of {len(blue)} in {len(blobs)} blob(s) click {int(cx * s)} {int(cy * s)}')
