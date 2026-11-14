#!/bin/bash
# tp.sh pid png gx gy : double-click the nexus near (gx,gy) until the teleport dialog shows, then confirm
cd "$(dirname "$0")"; mkdir -p shops
r=$(python -I nexus.py "$2" "$3" "$4"); echo "$r"
X=$(echo $r | awk '{print $(NF-1)}'); Y=$(echo $r | awk '{print $NF}')
U="pwsh -NoProfile -ExecutionPolicy Bypass -File ui.ps1 -GamePid $1"
for k in 1 2 3; do
  $U -Do dclick -X $X -Y $Y >/dev/null; sleep 2; $U -Do shot -Out shops/tpchk.png >/dev/null
  if python -I -c "
from PIL import Image
im=Image.open('shops/tpchk.png').convert('RGB'); c=im.crop((300,250,800,360))
import sys; px=[c.getpixel((x,y)) for x in range(0,500,10) for y in range(0,110,10)]
sys.exit(0 if sum(p[0] for p in px)/len(px) < 90 else 1)
"; then echo dialog; $U -Do key -Keys SPACE -HoldMs 150; exit 0; fi
done
echo "no dialog"; exit 1
