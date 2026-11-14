#!/bin/bash
# shopsession.sh : a fresh two-copy session (kit profiles) for the guest's shop and a market stall in Hernand.
#   launch, host to the Hernand nexus and down to the shop street, guest joins, travels to the nexus, walks to Delkin's
#   counter, holds R ("Shop"), buys one Water (3 coppers of the GUEST's money), leaves, and buys the Harvest Sack on
#   the stall next door (E held 2 s, 10 coppers). Prints what the guest's mod and packet log show; screenshots in shots/.
#   Checked on 1.0.0.3663, 14-nov (07:38-08:27). Nothing is sold: selling needs a look at the screen first.
cd "$(dirname "$0")"
B="D:/SteamLibrary/steamapps/common/Crimson Desert/bin64"
SP="$(cygpath -w "$(pwd)")"
mkdir -p shots
NX=-10626.4; NZ=-3813.3
# From the nexus to the shop street: round the garden wall, through the arch, down the street (a straight line from
# the nexus ends on top of the garden wall at (-10637.8, -3827.7)).
ROUTE="-10637.0 -3823.5 -10641.5 -3827.0 -10645.6 -3831.6 -10650.1 -3835.2 -10655.6 -3840.2 -10661.7 -3845.7 -10663.2 -3856.9 -10662.5 -3869.3"
tp() {  # pid role : fast travel to the Hernand nexus, three attempts
  for try in 1 2 3; do
    timeout 400 python -I map_tp.py $1 $2 $NX $NZ 2>&1 | tail -1
    for i in $(seq 1 30); do x=$(python -I posnow.py $1 2>/dev/null | cut -d' ' -f1); case "$x" in -1062*|-1063*) return 0;; esac; sleep 3; done
    pwsh -NoProfile -ExecutionPolicy Bypass -File ui.ps1 -GamePid $1 -Do key -Keys ESC -HoldMs 120 >/dev/null 2>&1; sleep 2
  done
  return 1
}
rm -f pids.txt
pwsh -NoProfile -ExecutionPolicy Bypass -File "$SP\\launch_house.ps1" > launch.txt 2>&1 < /dev/null
H=$(sed -n 's/.*pids host \([0-9]*\) guest \([0-9]*\).*/\1/p' pids.txt); G=$(sed -n 's/.*pids host \([0-9]*\) guest \([0-9]*\).*/\2/p' pids.txt)
echo "STAGE launch: pids $H $G at $(date +%T)"
[ -z "$H" ] && exit 1
UG="pwsh -NoProfile -ExecutionPolicy Bypass -File ui.ps1 -GamePid $G"
sleep 6; tp $H host || { echo "STAGE host tp FAILED: $(python -I posnow.py $H)"; exit 1; }
sleep 6; timeout 400 python -I walk.py $H -s 1.2 -n 8 $ROUTE 2>&1 | grep "^at" | tail -1
echo "STAGE host on the shop street at $(date +%T): $(python -I posnow.py $H | cut -c1-40)"
pwsh -NoProfile -ExecutionPolicy Bypass -File "$SP\\run_join.ps1" -Attach -AttachHost $H -AttachGuest $G > join.txt 2>&1
# run_join's "guest idle" can be False for a join that did succeed (a slow load): the position is the test.
for i in $(seq 1 40); do python -I posnow.py $G >/dev/null 2>&1 && break; sleep 5; done
python -I posnow.py $G >/dev/null 2>&1 || { echo "STAGE guest join FAILED"; exit 1; }
echo "STAGE guest in the world at $(date +%T): $(python -I posnow.py $G | cut -c1-60)"
sleep 8; tp $G guest || { echo "STAGE guest tp FAILED: $(python -I posnow.py $G)"; exit 1; }
sleep 6; timeout 400 python -I walk.py $G -s 1.2 -n 8 $ROUTE 2>&1 | grep "^at" | tail -1
timeout 120 python -I walk.py $G -s 0.5 -n 8 -10655.4 -3877.2 2>&1 | grep "^at"
timeout 30 python -I face.py $G -10650.0 -3881.5 >/dev/null 2>&1; sleep 0.8
echo "STAGE guest at the counter at $(date +%T): $(python -I posnow.py $G | cut -c1-40)"
PK=$(ls -t "$B"/cdmp_packets.guest_*.log | head -1)
n0=$(wc -l < "$B/cdmp.guest.log")
$UG -Do hold -Keys R -HoldMs 1500 >/dev/null 2>&1; sleep 4
$UG -Do shot -Out "$SP\\shots\\shop_menu.png" >/dev/null 2>&1
c=$(tail -n +$((n0+1)) "$B/cdmp.guest.log" | grep -a -c "GuestShopBranch")
echo "STAGE shop menu: $c GuestShopBranch line(s)"
[ "$c" = 0 ] && { echo "the shop did not open (look at shots/shop_menu.png: is the white 'R Shop' prompt there?)"; exit 1; }
$UG -Do key -Keys SPACE -HoldMs 120 >/dev/null 2>&1; sleep 4      # Buy
$UG -Do shot -Out "$SP\\shots\\shop_buy.png" >/dev/null 2>&1
p0=$(wc -l < "$PK")
$UG -Do key -Keys SPACE -HoldMs 120 >/dev/null 2>&1; sleep 2.5    # the first item (Water): the quantity dialog
$UG -Do key -Keys SPACE -HoldMs 120 >/dev/null 2>&1; sleep 3      # Confirm
$UG -Do shot -Out "$SP\\shots\\shop_bought.png" >/dev/null 2>&1
echo "STAGE buy: $(tail -n +$((p0+1)) "$PK" | grep -a -c -E "AddItemToInventoryAck") AddItemToInventoryAck"
$UG -Do key -Keys ESC -HoldMs 120 >/dev/null 2>&1; sleep 3        # back to the menu
$UG -Do key -Keys ESC -HoldMs 120 >/dev/null 2>&1; sleep 4        # Leave
tail -n +$((n0+1)) "$B/cdmp.guest.log" | grep -a "GuestShopBranch" | cut -c1-200
# The stall next to Delkin: "Harvest Sack  E Buy".
timeout 60 python -I walk.py $G -s 0.6 -n 5 -10652.6 -3875.6 2>&1 | grep "^at"
timeout 30 python -I face.py $G -10648.0 -3873.0 >/dev/null 2>&1; sleep 0.8
$UG -Do shot -Out "$SP\\shots\\stall_prompt.png" >/dev/null 2>&1
p0=$(wc -l < "$PK")
$UG -Do hold -Keys E -HoldMs 2000 >/dev/null 2>&1; sleep 3.5
tail -n +$((p0+1)) "$PK" | grep -a -E "Interaction(Preemption|Do)Step|CatchActionResult|ItemToInventory" | cut -c1-70
echo "DONE pids $H $G; ERR host $(grep -a -c '] ERR ' "$B/cdmp.host.log") guest $(grep -a -c '] ERR ' "$B/cdmp.guest.log"). Close the GUEST first."
