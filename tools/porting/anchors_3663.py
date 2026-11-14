#!/usr/bin/env python3
"""Anchors for the 3576 -> 3663 port (docs/research/port-3663.md). Read-only on the installed exe (1.0.0.3663).

The 3576 exe is gone, so the anchors come from the source itself: every byte array in src/mod with a 3527/3549 address
(port_near.arrays(): a trailing `// 0x...` comment or a same-named constant) is searched in the WHOLE 3663 image with
its relative operands masked (signature_map.relative_mask). A unique match is an anchor (3527 address -> 3663 address).
The 3576 port's own results (data/port_near_3576.json: each array's unique 3576 match) give the 3576 address of the
same bytes, so an anchor also maps 3576 -> 3663.

  python tools/porting/anchors_3663.py [--out tools/porting/data/anchors_3663.json]

Output: anchors sorted by 3576 address (when known), with the 3576->3663 shift, and the arrays with no or several
matches. Evidence only: each new address still needs its function read with capstone before a module admits 3663.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(ROOT / "tools" / "scripts"))
from rtti_dump import Pe
from signature_map import ImageScanner, relative_mask
from port_near import arrays


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--exe", type=Path, default=ROOT.parent / "bin64" / "CrimsonDesert.exe")
    ap.add_argument("--out", type=Path, default=Path(__file__).parent / "data" / "anchors_3663.json")
    args = ap.parse_args()
    data = args.exe.read_bytes()
    pe = Pe(data)
    if pe.timestamp != 0x6AF5D198:
        raise SystemExit(f"not 1.0.0.3663 (timestamp {pe.timestamp:#x})")
    scan = ImageScanner(pe, cap=20)
    near = json.loads((Path(__file__).parent / "data" / "port_near_3576.json").read_text(encoding="utf-8"))
    by3576 = {}
    for r in near["results"]:
        if r.get("status") == "unique":
            by3576[(r["file"], r["name"])] = int(r["near"][0], 16)
    anchors, other = [], []
    for it in arrays():
        if it["old"] is None or len(it["data"]) < 10:
            continue
        mask, _, _ = relative_mask(it["data"], it["old"])
        if sum(bool(x) for x in mask) < 10:
            continue
        matches, truncated = scan.scan(it["data"], mask)
        a3576 = by3576.get((it["file"], it["name"]))
        rec = {"file": it["file"], "line": it["line"], "name": it["name"], "old3527": hex(it["old"]),
               "at3576": hex(a3576) if a3576 is not None else None, "len": len(it["data"])}
        if len(matches) == 1 and not truncated:
            new = matches[0]["rva"]
            rec["at3663"] = hex(new)
            rec["shift3527"] = hex(new - it["old"])
            if a3576 is not None:
                rec["shift3576"] = hex(new - a3576)
            anchors.append(rec)
        else:
            rec["matches"] = [hex(m["rva"]) for m in matches[:20]]
            rec["truncated"] = truncated
            other.append(rec)
    anchors.sort(key=lambda r: int(r["at3576"] or r["old3527"], 16))
    out = {"exe": str(args.exe), "timestamp": hex(pe.timestamp), "anchor_count": len(anchors),
           "anchors": anchors, "not_unique": other}
    args.out.write_text(json.dumps(out, indent=1), encoding="utf-8")
    shifts = Counter(r.get("shift3576") for r in anchors)
    print(json.dumps({"anchors": len(anchors), "with_3576": sum(1 for r in anchors if r.get("at3576")),
                      "not_unique": len(other), "none": sum(1 for r in other if not r["matches"]),
                      "top_shifts_3576": shifts.most_common(12), "out": str(args.out)}, indent=1))


if __name__ == "__main__":
    main()
