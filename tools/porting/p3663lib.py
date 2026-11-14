"""Shared helpers for the 3576 -> 3663 port (read-only on the installed 1.0.0.3663 exe)."""
import bisect
import json
import re
import struct
import sys

ROOT = r'D:/SteamLibrary/steamapps/common/Crimson Desert/multi'
sys.path.insert(0, ROOT + '/tools/porting')
sys.path.insert(0, ROOT + '/tools/scripts')
from capstone import Cs, CS_ARCH_X86, CS_MODE_64  # noqa: E402
from signature_map import relative_mask  # noqa: E402

EXE = r'D:/SteamLibrary/steamapps/common/Crimson Desert/bin64/CrimsonDesert.exe'
BASE = 0x140000000
DATA = open(EXE, 'rb').read()
_pe = struct.unpack_from('<I', DATA, 0x3c)[0]
_n = struct.unpack_from('<H', DATA, _pe + 6)[0]
_opt = struct.unpack_from('<H', DATA, _pe + 20)[0]
SECS = []
for _i in range(_n):
    _o = _pe + 24 + _opt + _i * 40
    _vs, _va, _rs, _ra = struct.unpack_from('<IIII', DATA, _o + 8)
    _ch = struct.unpack_from('<I', DATA, _o + 36)[0]
    SECS.append((_va, _vs, _ra, _rs, _ch))
CODE = next(s for s in SECS if s[4] & 0x20000000 and not s[4] & 0x80000000)  # R-X, not RWX
MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = False


def off(rva):
    for va, vs, ra, rs, ch in SECS:
        if va <= rva < va + rs:
            return ra + rva - va
    return None


def rd(rva, n):
    o = off(rva)
    return DATA[o:o + n] if o is not None else None


def q(rva):
    b = rd(rva, 8)
    return struct.unpack('<Q', b)[0] if b else None


def dis(rva, n=40, stop_ret=True):
    out = []
    code = rd(rva, 0x800)
    for k, ins in enumerate(MD.disasm(code, BASE + rva)):
        out.append((ins.address - BASE, ins.size, ins.mnemonic, ins.op_str, bytes(ins.bytes)))
        if k + 1 >= n or (stop_ret and ins.mnemonic in ('ret', 'int3')):
            break
    return out


def rip_target(rva, ins_size, disp_off):
    disp = struct.unpack_from('<i', rd(rva + disp_off, 4))[0]
    return rva + ins_size + disp


_anch = json.load(open(ROOT + '/tools/porting/data/anchors_3663.json'))['anchors']
_A = sorted((int(a['old3527'], 16), int(a['at3663'], 16)) for a in _anch)
_AO = [a[0] for a in _A]


def shift_est(addr_old):
    """3527/3576 -> 3663 shift around an old code address: the nearest anchors below and above (3527-based)."""
    i = bisect.bisect_right(_AO, addr_old)
    lo = _A[i - 1] if i > 0 else None
    hi = _A[i] if i < len(_A) else None
    return (lo[1] - lo[0] if lo else None), (hi[1] - hi[0] if hi else None)


def pattern(data, old_addr):
    mask, _, _ = relative_mask(data, old_addr)
    return re.compile(b''.join(re.escape(bytes([b])) if m else b'.' for b, m in zip(data, mask)), re.S)


def near(addr_old, data, window=0x10000, old_for_mask=None):
    """Matches of `data` (relative fields masked) around addr_old + the anchor shift; sorted by distance."""
    lo, hi = shift_est(addr_old)
    shifts = [s for s in (lo, hi) if s is not None] or [0x40000]
    pat = pattern(data, old_for_mask if old_for_mask is not None else addr_old)
    hits = set()
    for s in set(shifts):
        c = addr_old + s
        o1, o2 = off(max(CODE[0], c - window)), off(c + window)
        if o1 is None or o2 is None:
            continue
        for m in pat.finditer(DATA, o1, o2):
            hits.add(c - window + (m.start() - o1) if off(c - window) == o1 else None)
    hits.discard(None)
    mid = addr_old + (sum(shifts) // len(shifts))
    return sorted(hits, key=lambda h: abs(h - mid)), shifts


def whole(data, old_addr, cap=20):
    pat = pattern(data, old_addr)
    va, vs, ra, rs, ch = CODE
    res = []
    for m in pat.finditer(DATA, ra, ra + rs):
        res.append(va + m.start() - ra)
        if len(res) >= cap:
            break
    return res


VMAP = json.load(open(ROOT + '/tools/porting/data/vtable_map_3576_3663.json'))


def vt3663(vt3576):
    v = VMAP.get(hex(vt3576))
    return int(v, 16) if v else None


def slot(vt_rva, k):
    p = q(vt_rva + 8 * k)
    return p - BASE if p else None


def count_refs(target, cap=5000):
    """RIP-relative references to `target` in the code section (disp32 scan on common load/store/lea forms)."""
    va, vs, ra, rs, ch = CODE
    n = 0
    # mov/lea reg, [rip+disp] = 48/4C 8B/8D modrm(05|0D|15|1D|25|2D|35|3D) disp32
    pat = re.compile(rb'[\x48\x4C][\x8B\x8D\x89\x3B\x39][\x05\x0D\x15\x1D\x25\x2D\x35\x3D]', re.S)
    for m in pat.finditer(DATA, ra, ra + rs - 8):
        i = m.start()
        disp = struct.unpack_from('<i', DATA, i + 3)[0]
        if va + (i - ra) + 7 + disp == target:
            n += 1
            if n >= cap:
                break
    return n
