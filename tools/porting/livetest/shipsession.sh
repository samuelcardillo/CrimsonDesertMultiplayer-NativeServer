#!/bin/bash
# shipsession.sh [stage] [H G] : a fresh two-copy session up to "host at the ship's wheel, guest on the stern deck".
#   stages: launch (default: everything), hopkins, join, guestboard, hostboard. A later stage needs the pids.
#   deploy + launch, host to Vellua, Hopkins (R held 2 s at the tested spot), ship retrieved, guest joins and boards by
#   the port ladder, host boards and takes the wheel. Each stage prints one line; stops at the first that fails.
cd "$(dirname "$0")"
B="D:/SteamLibrary/steamapps/common/Crimson Desert/bin64"
SP="$(cygpath -w "$(pwd)")"
STAGE=${1:-launch}; H=$2; G=$3
order="launch hopkins join guestboard hostboard"
from() { case " ${order#*$STAGE} " in *" $1 "*) return 0;; esac; [ "$1" = "$STAGE" ]; }

tp() {  # pid role : fast travel to the Vellua nexus, three attempts
  for try in 1 2 3; do
    timeout 400 python -I map_tp.py $1 $2 -10623.2 -6109.3 2>&1 | tail -1
    for i in $(seq 1 30); do x=$(python -I posnow.py $1 2>/dev/null | cut -d' ' -f1); case "$x" in -106*) return 0;; esac; sleep 3; done
    pwsh -NoProfile -ExecutionPolicy Bypass -File ui.ps1 -GamePid $1 -Do key -Keys ESC -HoldMs 120 >/dev/null 2>&1; sleep 2
  done
  return 1
}
board() {  # pid : swim to the port side, climb the ladder (the point and the heading are taken in the ship's frame)
  local P=$1; local UU="pwsh -NoProfile -ExecutionPolicy Bypass -File ui.ps1 -GamePid $P"
  timeout 280 python -I walk.py $P -s 1.5 -n 8 -10455.5 -6186 -10430 -6196 -10402 -6203 2>&1 | grep "^at" | tail -1
  set -- $(python -I shiplocal.py $P -9.0 -7.7 -5.3 -4.3 -3.0 -4.21)
  timeout 240 python -I walk.py $P -s 1.2 -n 14 $1 $2 2>&1 | grep "^at" | tail -1
  set -- $(python -I shiplocal.py $P -9.0 -7.7 -5.3 -4.3 -3.0 -4.21)
  timeout 160 python -I walk.py $P -s 0.45 -n 10 $3 $4 2>&1 | grep "^at" | tail -1
  set -- $(python -I shiplocal.py $P -9.0 -7.7 -5.3 -4.3 -3.0 -4.21)
  timeout 40 python -I face.py $P $5 $6 >/dev/null 2>&1
  $UU -Do hold -Keys W -HoldMs 3500 >/dev/null 2>&1; sleep 1; $UU -Do hold -Keys W -HoldMs 3000 >/dev/null 2>&1; sleep 1.5
  $UU -Do hold -Keys W -HoldMs 900 >/dev/null 2>&1; sleep 1
}

if from launch; then
  rm -f pids.txt launchX.txt
  pwsh -NoProfile -ExecutionPolicy Bypass -File "$SP\launch_house.ps1" > launchX.txt 2>&1 < /dev/null &
  for i in $(seq 1 200); do grep -q "host in world" launchX.txt 2>/dev/null && break; grep -q -E "launch failed|is gone|Exception" launchX.txt 2>/dev/null && { tail -c 800 launchX.txt; exit 1; }; sleep 2; done
  H=$(sed -n 's/.*pids host \([0-9]*\) guest \([0-9]*\).*/\1/p' pids.txt); G=$(sed -n 's/.*pids host \([0-9]*\) guest \([0-9]*\).*/\2/p' pids.txt)
  echo "STAGE launch: pids $H $G; host in world at $(date +%T); asi $(certutil -hashfile "$B/cdmp.asi" SHA256 | sed -n 2p | cut -c1-8)"
  [ -z "$H" ] && exit 1
fi
U="pwsh -NoProfile -ExecutionPolicy Bypass -File ui.ps1 -GamePid $H"
UG="pwsh -NoProfile -ExecutionPolicy Bypass -File ui.ps1 -GamePid $G"

if from hopkins; then
  if [ "$STAGE" = "launch" ]; then
    sleep 6; tp $H host || { echo "STAGE host tp FAILED: $(python -I posnow.py $H)"; exit 1; }
    sleep 6
    timeout 280 python -I goto3576.py $H -10480 -6150 3 40 2>&1 | tail -1
    timeout 200 python -I walk.py $H -s 0.7 -n 8 -10476.5 -6142.8 -10475.5 -6139.6 -10472.5 -6138.5 2>&1 | grep "^at" | tail -1
  fi
  # the stance: x between -10472.0 and -10471.4 at z -6138.3 (the prompt is white there); the aim, then strafes east
  # the stance: from exactly (-10472.65, -6138.72), facing Hopkins, strafes to the left until x is east of -10472.0
  # (ends near (-10471.9, -6138.0): the prompt is white there; 0.3 m further north it is not)
  timeout 90 python -I walk.py $H -s 0.2 -n 6 -10473.3 -6138.6 -10472.65 -6138.72 2>&1 | grep "^at" | tail -1
  for n in 1 2 3 4 5; do
    timeout 40 python -I face.py $H -10468.0 -6145.0 >/dev/null 2>&1
    x=$(python -I posnow.py $H | cut -d' ' -f1)
    python -I -c "import sys; sys.exit(0 if float('$x') > -10472.0 else 1)" && break
    $U -Do hold -Keys A -HoldMs 230 >/dev/null 2>&1; sleep 0.8
  done
  # ... and not north of z -6137.97 (at -6137.90 the focus falls on a sack): short steps towards Hopkins
  for n in 1 2 3; do
    timeout 40 python -I face.py $H -10468.0 -6145.0 >/dev/null 2>&1
    z=$(python -I posnow.py $H | cut -d' ' -f3)
    python -I -c "import sys; sys.exit(0 if float('$z') < -6137.97 else 1)" && break
    $U -Do hold -Keys W -HoldMs 200 >/dev/null 2>&1; sleep 0.8
  done
  timeout 40 python -I face.py $H -10468.0 -6145.0 >/dev/null 2>&1
  $U -Do look -Dx 10 -Dy 20 -Steps 3 >/dev/null 2>&1; sleep 0.8
  echo "STAGE host at Hopkins at $(date +%T): $(python -I posnow.py $H | cut -c1-40)"
  $U -Do shot -Out "$SP\\shots\\ss_hop_a.png" >/dev/null 2>&1
  $U -Do hold -Keys R -HoldMs 2000 >/dev/null 2>&1; sleep 3
  $U -Do shot -Out "$SP\\shots\\ss_hop_b.png" >/dev/null 2>&1
  $U -Do key -Keys SPACE -HoldMs 120 >/dev/null 2>&1; sleep 4
  $U -Do key -Keys SPACE -HoldMs 120 >/dev/null 2>&1; sleep 6
  $U -Do key -Keys ESC -HoldMs 120 >/dev/null 2>&1; sleep 4
  PARTS=$(timeout 60 python -I shipparts.py $H 2>/dev/null | wc -l)
  echo "STAGE ship: $PARTS actors hang from 0xB010000A on the host at $(date +%T)"
  [ "$PARTS" -lt 5 ] && { echo "STAGE ship FAILED (see shots/ss_hop_*.png)"; exit 1; }
fi

if from join; then
  pwsh -NoProfile -ExecutionPolicy Bypass -File "$SP\run_join.ps1" -Attach -AttachHost $H -AttachGuest $G > joinV.txt 2>&1
  J=$(grep -E 'guest idle|GONE' joinV.txt | sed 's/\x1b\[[0-9;]*m//g' | tail -1)
  echo "STAGE guest join: $J at $(date +%T)"
  # "guest idle: False" can be a slow load that did succeed: the test is whether the guest has a position.
  case "$J" in *True*) ;; *) ok=0; for i in $(seq 1 36); do python -I posnow.py $G >/dev/null 2>&1 && { ok=1; break; }; sleep 5; done
    [ $ok = 1 ] || { echo "STAGE guest join FAILED"; exit 1; }; echo "STAGE guest join: in the world after all at $(date +%T)";; esac
  sleep 4; tp $G guest || { echo "STAGE guest tp FAILED: $(python -I posnow.py $G)"; exit 1; }
  sleep 6
  timeout 280 python -I goto3576.py $G -10480 -6150 3 40 2>&1 | tail -1
  timeout 280 python -I walk.py $G -s 1.5 -n 8 -10463 -6148 -10457 -6160 -10457.5 -6176 2>&1 | grep "^at" | tail -1
  echo "STAGE guest on the quay at $(date +%T): $(python -I posnow.py $G | cut -c1-40)"
fi

if from guestboard; then
  board $G
  echo "STAGE guest ladder at $(date +%T): $(python -I posnow.py $G)"
  timeout 220 python -I shipwalk.py $G -s 0.4 -n 9 -2.9 -1.2 -2.85 0.6 -2.8 3.6 -1.2 4.6 2>&1 | grep "^at" | tail -1
  echo "STAGE guest on deck at $(date +%T): $(python -I posnow.py $G)"
fi

if from hostboard; then
  timeout 280 python -I walk.py $H -s 1.5 -n 8 -10463 -6141.5 -10457 -6160 -10457.5 -6176 2>&1 | grep "^at" | tail -1
  board $H
  echo "STAGE host ladder at $(date +%T): $(python -I posnow.py $H)"
  timeout 280 python -I shipwalk.py $H -s 0.35 -n 9 -2.9 -3.5 -2.9 -1.2 -2.85 0.6 -2.78 2.27 2>&1 | grep "^at" | tail -1
  timeout 60 python -I shipwalk.py $H -s 2.2 -n 2 0.0 1.85 2>&1 | tail -1
  sleep 0.5; $U -Do shot -Out "$SP\\shots\\ss_helm_a.png" >/dev/null 2>&1
  $U -Do key -Keys E -HoldMs 150 >/dev/null 2>&1; sleep 4
  echo "STAGE host helm at $(date +%T): $(python -I posnow.py $H)"
fi
echo "DONE pids $H $G"
