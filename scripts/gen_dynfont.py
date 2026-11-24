#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Generate standard PSF2 (.psfu) Unicode console fonts from GNU Unifont .hex or OpenType Bitmap .otb."""

import argparse
import gzip
import struct
import sys
from pathlib import Path

PSF2_MAGIC = bytes((0x72, 0xB5, 0x4A, 0x86))
PSF2_V1_VERSION = 1
PSF2_V1_HEADER_SIZE = 36
PSF2_HAS_UNICODE_TABLE = 0x01
BASE_WIDTH = 8
BASE_HEIGHT = 16
HEX_LEN_8X16 = 32
HEX_LEN_16X16 = 64
MAX_UCS = 0x10FFFF


def open_text(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="ascii")
    return path.open("r", encoding="ascii")


def make_expand_table(factor: int) -> list[bytes]:
    """Build a 256-entry lookup table expanding each bit of a byte `factor` times."""
    tbl = []
    for byte in range(256):
        val = 0
        for bit in range(8):
            val <<= factor
            if byte & (0x80 >> bit):
                val |= (1 << factor) - 1
        tbl.append(val.to_bytes(factor, "big"))
    return tbl


def scale_glyph(
    raw: bytes,
    src_w: int,
    src_h: int,
    dst_w: int,
    dst_h: int,
    expand_tbl: list[bytes] | None = None,
) -> bytes:
    """Scale a monochrome bitmap from src_w x src_h to dst_w x dst_h."""
    if expand_tbl is not None and dst_w % src_w == 0 and dst_h % src_h == 0:
        v_factor = dst_h // src_h
        src_pitch = (src_w + 7) // 8
        out = bytearray()
        for sy in range(src_h):
            row = b"".join(
                expand_tbl[raw[sy * src_pitch + bx]] for bx in range(src_pitch)
            )
            out.extend(row * v_factor)
        return bytes(out)

    src_pitch = (src_w + 7) // 8
    dst_pitch = (dst_w + 7) // 8
    out = bytearray(dst_pitch * dst_h)

    for dy in range(dst_h):
        sy0 = (dy * src_h) // dst_h
        sy1 = max(sy0 + 1, ((dy + 1) * src_h) // dst_h)
        for dx in range(dst_w):
            sx0 = (dx * src_w) // dst_w
            sx1 = max(sx0 + 1, ((dx + 1) * src_w) // dst_w)
            lit = False
            for sy in range(sy0, sy1):
                for sx in range(sx0, sx1):
                    if raw[sy * src_pitch + (sx >> 3)] & (0x80 >> (sx & 7)):
                        lit = True
                        break
                if lit:
                    break
            if lit:
                out[dy * dst_pitch + (dx >> 3)] |= 0x80 >> (dx & 7)
    return bytes(out)


def parse_otb_cmap(data: bytes, cmap_off: int) -> dict[int, int]:
    """Parse OpenType cmap table (format 4 and format 12) into {ucs: glyph_id}."""
    _, num_sub = struct.unpack_from(">HH", data, cmap_off)
    subtables: list[tuple[int, int]] = []
    for i in range(num_sub):
        pid, eid, off = struct.unpack_from(">HHI", data, cmap_off + 4 + i * 8)
        fmt, = struct.unpack_from(">H", data, cmap_off + off)
        if fmt in (4, 12) and (pid == 0 or (pid == 3 and eid in (1, 10))):
            subtables.append((fmt, cmap_off + off))

    # Prefer format 12 (full Unicode) over format 4 (BMP)
    subtables.sort(key=lambda x: x[0], reverse=True)
    if not subtables:
        raise ValueError("No supported Unicode cmap subtable (format 4 or 12) found")

    fmt, off = subtables[0]
    mapping: dict[int, int] = {}

    if fmt == 12:
        _, _, _, _, num_groups = struct.unpack_from(">HHIII", data, off)
        pos = off + 16
        for _ in range(num_groups):
            start_c, end_c, start_g = struct.unpack_from(">III", data, pos)
            pos += 12
            for c in range(start_c, min(end_c, MAX_UCS) + 1):
                mapping[c] = start_g + (c - start_c)
    else:
        seg_count_x2, = struct.unpack_from(">H", data, off + 6)
        seg_count = seg_count_x2 // 2
        end_off = off + 14
        start_off = end_off + seg_count_x2 + 2
        delta_off = start_off + seg_count_x2
        range_off = delta_off + seg_count_x2
        for i in range(seg_count):
            end_c, = struct.unpack_from(">H", data, end_off + i * 2)
            start_c, = struct.unpack_from(">H", data, start_off + i * 2)
            delta, = struct.unpack_from(">h", data, delta_off + i * 2)
            ro_pos = range_off + i * 2
            ro, = struct.unpack_from(">H", data, ro_pos)
            if start_c == 0xFFFF and end_c == 0xFFFF:
                continue
            for c in range(start_c, end_c + 1):
                if ro == 0:
                    gid = (c + delta) & 0xFFFF
                else:
                    gid_pos = ro_pos + ro + (c - start_c) * 2
                    gid, = struct.unpack_from(">H", data, gid_pos)
                    if gid:
                        gid = (gid + delta) & 0xFFFF
                if gid:
                    mapping[c] = gid

    return mapping


def load_otb(in_path: Path, scale: int) -> tuple[int, int, dict[int, bytes]]:
    """Load monochrome bitmaps from an OpenType Bitmap (.otb) file."""
    data = in_path.read_bytes()
    _, num_tables = struct.unpack_from(">IH", data, 0)
    tables: dict[str, tuple[int, int]] = {}
    for i in range(num_tables):
        tag, _, off, length = struct.unpack_from(">4sIII", data, 12 + i * 16)
        tables[tag.decode("ascii")] = (off, length)

    for req in ("cmap", "EBLC", "EBDT"):
        if req not in tables:
            raise ValueError(f"{in_path}: missing required SFNT table '{req}'")

    cmap = parse_otb_cmap(data, tables["cmap"][0])
    eblc_off = tables["EBLC"][0]
    ebdt_off = tables["EBDT"][0]

    _, num_sizes = struct.unpack_from(">II", data, eblc_off)
    if num_sizes < 1:
        raise ValueError(f"{in_path}: EBLC has no bitmap strikes")

    idx_sub_off, _, num_sub, _ = struct.unpack_from(">IIII", data, eblc_off + 8)
    _, _, bit_depth, _ = struct.unpack_from(">BBBB", data, eblc_off + 8 + 44)
    if bit_depth != 1:
        raise ValueError(f"{in_path}: only 1-bit monochrome OTB supported (got {bit_depth})")

    gid_bitmaps: dict[int, bytes] = {}
    cell_w = 0
    cell_h = 0

    for s in range(num_sub):
        fg, lg, add_off = struct.unpack_from(">HHI", data, eblc_off + idx_sub_off + s * 8)
        sub_off = eblc_off + idx_sub_off + add_off
        idx_fmt, img_fmt, img_data_off = struct.unpack_from(">HHI", data, sub_off)

        if idx_fmt == 2:
            img_size, mh, mw, _, _, _ = struct.unpack_from(">IBBbbB", data, sub_off + 8)
            if not cell_w:
                cell_w, cell_h = mw, mh
            pitch = (cell_w + 7) // 8
            for gid in range(fg, lg + 1):
                g_off = ebdt_off + img_data_off + (gid - fg) * img_size
                if img_fmt == 1:
                    # 5-byte SmallGlyphMetrics + byte-aligned bitmap
                    bm = data[g_off + 5 : g_off + 5 + pitch * cell_h]
                elif img_fmt == 5:
                    # Raw byte-aligned bitmap (metrics in EBLC)
                    bm = data[g_off : g_off + pitch * cell_h]
                else:
                    raise ValueError(f"{in_path}: unsupported EBDT imageFormat {img_fmt}")
                if len(bm) == pitch * cell_h:
                    gid_bitmaps[gid] = bm
        else:
            raise ValueError(f"{in_path}: unsupported EBLC indexFormat {idx_fmt}")

    if not cell_w or not cell_h:
        raise ValueError(f"{in_path}: could not determine glyph geometry")

    dst_w = cell_w * scale
    dst_h = cell_h * scale
    expand_tbl = make_expand_table(scale) if scale > 1 else None

    glyphs: dict[int, bytes] = {}
    for cp, gid in cmap.items():
        bm = gid_bitmaps.get(gid)
        if bm is None:
            continue
        if scale > 1:
            bm = scale_glyph(bm, cell_w, cell_h, dst_w, dst_h, expand_tbl)
        glyphs[cp] = bm

    return dst_w, dst_h, glyphs


def load_hex(
    in_path: Path, scale: int, downscale_wide: bool
) -> tuple[int, int, dict[int, bytes], int]:
    """Load glyphs from GNU Unifont .hex[.gz]."""
    dst_w = BASE_WIDTH * scale
    dst_h = BASE_HEIGHT * scale
    narrow_tbl = make_expand_table(scale) if scale > 1 else None
    wide_tbl = make_expand_table(scale // 2) if scale >= 2 and scale % 2 == 0 else None

    glyphs: dict[int, bytes] = {}
    skipped_wide = 0

    with open_text(in_path) as f:
        for raw in f:
            line = raw.strip()
            if not line or ":" not in line:
                continue
            code_s, hex_s = line.split(":", 1)
            cp = int(code_s, 16)
            if cp > MAX_UCS:
                continue

            if len(hex_s) == HEX_LEN_8X16:
                bm = bytes.fromhex(hex_s)
                if scale > 1:
                    bm = scale_glyph(bm, 8, 16, dst_w, dst_h, narrow_tbl)
                glyphs[cp] = bm
            elif len(hex_s) == HEX_LEN_16X16 and downscale_wide:
                bm = bytes.fromhex(hex_s)
                glyphs[cp] = scale_glyph(bm, 16, 16, dst_w, dst_h, wide_tbl)
            else:
                skipped_wide += 1

    return dst_w, dst_h, glyphs, skipped_wide


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert GNU Unifont .hex[.gz] or OpenType Bitmap .otb to standard PSF2 (.psfu)."
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="/usr/share/unifont/unifont.hex",
        help="Input .hex, .hex.gz, or .otb font file (default: %(default)s)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="dynfont-8x16.psfu",
        help="Output PSF2 (.psfu) font file (default: %(default)s)",
    )
    parser.add_argument(
        "--scale",
        type=int,
        default=1,
        choices=range(1, 9),
        help="Integer scale factor (1..8; default: 1)",
    )
    parser.add_argument(
        "--downscale-wide",
        action="store_true",
        help="For Unifont .hex: fit 16x16 wide glyphs into target cell width",
    )
    args = parser.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)

    if in_path.suffix.lower() == ".otb":
        dst_w, dst_h, glyphs = load_otb(in_path, args.scale)
        skipped_wide = 0
    else:
        dst_w, dst_h, glyphs, skipped_wide = load_hex(
            in_path, args.scale, args.downscale_wide
        )

    if dst_w > 64 or dst_h > 128:
        parser.error(f"resulting glyph size {dst_w}x{dst_h} exceeds 64x128 limit")

    # Deduplicate identical bitmaps and build a sorted {ucs, glyph_idx} index
    bm_to_gid: dict[bytes, int] = {}
    bitmaps: list[bytes] = []
    index_entries: list[bytes] = []

    for cp in sorted(glyphs):
        bm = glyphs[cp]
        gid = bm_to_gid.get(bm)
        if gid is None:
            gid = len(bitmaps)
            bm_to_gid[bm] = gid
            bitmaps.append(bm)
        index_entries.append(struct.pack("<II", cp, gid))

    charsize = ((dst_w + 7) // 8) * dst_h
    hdr = PSF2_MAGIC + struct.pack(
        "<8I",
        PSF2_V1_VERSION,
        PSF2_V1_HEADER_SIZE,
        PSF2_HAS_UNICODE_TABLE,
        len(bitmaps),
        charsize,
        dst_h,
        dst_w,
        len(index_entries),
    )
    data = hdr + b"".join(bitmaps) + b"".join(index_entries)
    out_path.write_bytes(data)

    print(
        f"Wrote {out_path} ({len(data)} bytes, PSF2 v1 {dst_w}x{dst_h}): "
        f"{len(bitmaps)} unique glyphs, {len(index_entries)} sorted mappings"
        + (f", {skipped_wide} wide skipped" if skipped_wide else "")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
