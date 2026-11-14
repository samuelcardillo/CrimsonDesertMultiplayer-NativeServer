#!/bin/bash
# hop.sh H [holdms] [shot] : aim the host at Hopkins (Vellua ship manager) and hold R; a screenshot afterwards.
cd "$(dirname "$0")"
SP="$(cygpath -w "$(pwd)")"
B="D:/SteamLibrary/steamapps/common/Crimson Desert/bin64"
H=$1; MS=${2:-2000}; OUT=${3:-hop}
U="pwsh -NoProfile -ExecutionPolicy Bypass -File ui.ps1 -GamePid $H"
grep -a "Local: pos" "$B/cdmp.host.log" | tail -1 | cut -c32-90
timeout 40 python -I face.py $H -10468.0 -6145.0 >/dev/null 2>&1
$U -Do look -Dx 30 -Dy 50 -Steps 3 >/dev/null 2>&1
sleep 1
$U -Do shot -Out "$SP\\shots\\${OUT}_a.png" >/dev/null 2>&1
if [ "$MS" != "0" ]; then
  $U -Do hold -Keys R -HoldMs $MS >/dev/null 2>&1
  sleep 3
  $U -Do shot -Out "$SP\\shots\\${OUT}_b.png" >/dev/null 2>&1
fi
echo "done $(date +%T)"
