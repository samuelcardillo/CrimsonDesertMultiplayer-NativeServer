"""The installed game's build: the world slot and the camera slot of 3576 or 3663 (read from the exe's PE timestamp)."""
import struct

_EXE = r'D:/SteamLibrary/steamapps/common/Crimson Desert/bin64/CrimsonDesert.exe'
with open(_EXE, 'rb') as _f:
    _h = _f.read(0x400)
_pe = struct.unpack_from('<I', _h, 0x3C)[0]
TIMESTAMP = struct.unpack_from('<I', _h, _pe + 8)[0]
if TIMESTAMP == 0x6AF5D198:      # 1.0.0.3663 (2026-11-13)
    WORLD_SLOT, CAMERA_SLOT, BUILD = 0x72451C0, 0x71602A8, 3663
elif TIMESTAMP == 0x6AED2E85:    # 1.0.0.3576
    WORLD_SLOT, CAMERA_SLOT, BUILD = 0x71C0100, 0x70DC130, 3576
else:
    raise SystemExit(f'unknown game build (PE timestamp {TIMESTAMP:#x})')
