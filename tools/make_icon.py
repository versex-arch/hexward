"""Generate src/hexward/hexward.ico with no third-party libraries.

The mark: a dark rounded tile with an emerald hexagon ("hex" + "ward") and a
check inside it - the same shape and colour as the logo in the app.

Run from the repository root:  python tools/make_icon.py
"""

import math
import struct
from pathlib import Path

SIZES = (16, 24, 32, 48, 64, 128)
SS = 4  # supersampling factor for anti-aliasing

TILE = (14, 15, 18)
RIM = (38, 40, 47)
HEX_TOP, HEX_BOTTOM = (74, 222, 170), (16, 172, 120)
CHECK = (6, 28, 19)

HEX = [(0.5 + 0.345 * math.cos(math.radians(90 + 60 * k)), 0.5 - 0.345 * math.sin(math.radians(90 + 60 * k)))
       for k in range(6)]
CHECK_PATH = [(0.372, 0.515), (0.462, 0.602), (0.634, 0.415)]


def in_tile(x: float, y: float, inset: float = 0.0) -> bool:
    lo, hi, r = 0.03 + inset, 0.97 - inset, 0.235 - inset
    if not (lo <= x <= hi and lo <= y <= hi):
        return False
    cx = min(max(x, lo + r), hi - r)
    cy = min(max(y, lo + r), hi - r)
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r


def in_hex(x: float, y: float) -> bool:
    sign = 0
    for i in range(6):
        (x1, y1), (x2, y2) = HEX[i], HEX[(i + 1) % 6]
        cross = (x2 - x1) * (y - y1) - (y2 - y1) * (x - x1)
        if cross:
            if sign and (cross > 0) != (sign > 0):
                return False
            sign = 1 if cross > 0 else -1
    return True


def near_check(x: float, y: float, half: float) -> bool:
    for (x1, y1), (x2, y2) in zip(CHECK_PATH, CHECK_PATH[1:]):
        dx, dy = x2 - x1, y2 - y1
        t = max(0.0, min(1.0, ((x - x1) * dx + (y - y1) * dy) / (dx * dx + dy * dy)))
        if (x - x1 - t * dx) ** 2 + (y - y1 - t * dy) ** 2 <= half * half:
            return True
    return False


def pixel(x: float, y: float, small: bool):
    if not in_tile(x, y):
        return None
    if in_hex(x, y):
        if near_check(x, y, 0.05 if small else 0.042):
            return CHECK
        t = (y - 0.155) / 0.69
        return tuple(round(a + (b - a) * t) for a, b in zip(HEX_TOP, HEX_BOTTOM))
    return TILE if in_tile(x, y, 0.022) else RIM


def image(size: int) -> bytes:
    rows = []
    for py in range(size):
        row = bytearray()
        for px in range(size):
            r = g = b = hits = 0
            for sy in range(SS):
                for sx in range(SS):
                    c = pixel((px + (sx + 0.5) / SS) / size, (py + (sy + 0.5) / SS) / size, size <= 24)
                    if c:
                        r, g, b, hits = r + c[0], g + c[1], b + c[2], hits + 1
            if hits:
                row += bytes((round(b / hits), round(g / hits), round(r / hits), round(hits * 255 / (SS * SS))))
            else:
                row += b"\x00\x00\x00\x00"
        rows.append(bytes(row))
    pixels = b"".join(reversed(rows))  # BMP rows are bottom-up
    mask = b"\x00" * (((size + 31) // 32) * 4 * size)
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, len(pixels) + len(mask), 0, 0, 0, 0)
    return header + pixels + mask


def main() -> None:
    images = [image(s) for s in SIZES]
    out = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    for size, data in zip(SIZES, images):
        out += struct.pack("<BBBBHHII", size, size, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    dest = Path(__file__).resolve().parent.parent / "src" / "hexward" / "hexward.ico"
    dest.write_bytes(out + b"".join(images))
    print(f"wrote {dest} ({dest.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
