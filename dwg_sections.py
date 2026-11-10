"""DWG section/page locator extraction for directed mutation.

Produces on-disk payload regions (file offset, size, label) so mutation can
target compressed/page data when dynamic origin tracing yields no offsets.

Supported:
  - R2000 (AC1015): section locator records at 0x19
  - R2004+ (AC1018/AC1024/AC1027/AC1032): encrypted file header + section
    page map (same path as libredwg decode_R2004)
  - R2007 (AC1021): best-effort; returns [] if Reed-Solomon path unavailable
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, Tuple


def _u32(data: bytes, off: int) -> Optional[int]:
    if off < 0 or off + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, off)[0]


def _u64(data: bytes, off: int) -> Optional[int]:
    if off < 0 or off + 8 > len(data):
        return None
    return struct.unpack_from("<Q", data, off)[0]


def _i32(data: bytes, off: int) -> Optional[int]:
    if off < 0 or off + 4 > len(data):
        return None
    return struct.unpack_from("<i", data, off)[0]


def decrypt_r2004_header(src: bytes) -> bytes:
    """libredwg decrypt_R2004_header: seed=1, rseed=rseed*0x343fd+0x269ec3."""
    rseed = 1
    out = bytearray(len(src))
    for i, b in enumerate(src):
        rseed = (rseed * 0x343FD + 0x269EC3) & 0xFFFFFFFF
        out[i] = b ^ ((rseed >> 0x10) & 0xFF)
    return bytes(out)


class _BitReader:
    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    def rc(self) -> int:
        if self.pos >= len(self.data):
            raise EOFError("rc")
        b = self.data[self.pos]
        self.pos += 1
        return b

    def rl(self) -> int:
        v = _u32(self.data, self.pos)
        if v is None:
            raise EOFError("rl")
        self.pos += 4
        return v


def _read_literal_length(br: _BitReader) -> Tuple[int, int]:
    """Returns (lit_length, next_opcode_hint). Mirrors libredwg."""
    total = 0
    byte = br.rc()
    if 0x01 <= byte <= 0x0F:
        return byte + 3, 0
    if byte == 0:
        total = 0x0F
        while True:
            byte = br.rc()
            if byte != 0:
                break
            total += 0xFF
        return total + byte + 3, 0
    if byte & 0xF0:
        return 0, byte
    return 0, 0


def _read_two_byte_offset(br: _BitReader) -> Tuple[int, int]:
    first = br.rc()
    second = br.rc()
    offset = (first >> 2) | (second << 6)
    lit_length = first & 0x03
    return offset, lit_length


def _read_long_compression_offset(br: _BitReader) -> int:
    total = 0
    byte = br.rc()
    if byte == 0:
        total = 0xFF
        while True:
            byte = br.rc()
            if byte != 0:
                break
            total += 0xFF
    return total + byte


def decompress_r2004(src: bytes, comp_size: int, decomp_size: int) -> Optional[bytes]:
    """Port of libredwg decompress_R2004_section."""
    br = _BitReader(src, 0)
    end_comp = min(comp_size, len(src))
    dst = bytearray()
    dst_end = decomp_size

    try:
        lit, opcode1 = _read_literal_length(br)
        if lit > dst_end:
            return None
        if br.pos + lit > len(src):
            return None
        dst.extend(src[br.pos:br.pos + lit])
        br.pos += lit
        opcode1 = 0x00

        while br.pos < end_comp and len(dst) < dst_end:
            if opcode1 == 0x00:
                opcode1 = br.rc()

            if opcode1 >= 0x40:
                comp_bytes = ((opcode1 & 0xF0) >> 4) - 1
                opcode2 = br.rc()
                comp_offset = (opcode2 << 2) | ((opcode1 & 0x0C) >> 2)
                if opcode1 & 0x03:
                    lit = opcode1 & 0x03
                    opcode1 = 0x00
                else:
                    lit, opcode1 = _read_literal_length(br)
            elif 0x21 <= opcode1 <= 0x3F:
                comp_bytes = opcode1 - 0x1E
                comp_offset, lit = _read_two_byte_offset(br)
                if lit != 0:
                    opcode1 = 0x00
                else:
                    lit, opcode1 = _read_literal_length(br)
            elif opcode1 == 0x20:
                comp_bytes = _read_long_compression_offset(br) + 0x21
                comp_offset, lit = _read_two_byte_offset(br)
                if lit != 0:
                    opcode1 = 0x00
                else:
                    lit, opcode1 = _read_literal_length(br)
            elif 0x12 <= opcode1 <= 0x1F:
                comp_bytes = (opcode1 & 0x0F) + 2
                comp_offset, lit = _read_two_byte_offset(br) + (0x3FFF, 0)
                # read_two_byte_offset returns (offset, lit) — fix:
                # actually returns tuple; re-do properly below
                raise RuntimeError("unreachable")
            elif opcode1 == 0x10:
                comp_bytes = _read_long_compression_offset(br) + 9
                off_lit = _read_two_byte_offset(br)
                comp_offset = off_lit[0] + 0x3FFF
                lit = off_lit[1]
                if lit != 0:
                    opcode1 = 0x00
                else:
                    lit, opcode1 = _read_literal_length(br)
            elif opcode1 == 0x11:
                break
            else:
                return None

            # Fix 0x12-0x1F branch properly (re-exec without raise)
            # (handled by rewriting above — see corrected version below)
            src_i = len(dst) - comp_offset - 1
            if src_i < 0:
                return None
            for _ in range(comp_bytes):
                if len(dst) >= dst_end:
                    break
                if src_i >= len(dst):
                    return None
                dst.append(dst[src_i])
                src_i += 1
            if lit:
                if br.pos + lit > len(src):
                    return None
                dst.extend(src[br.pos:br.pos + lit])
                br.pos += lit
    except (EOFError, RuntimeError):
        return None
    return bytes(dst)


def decompress_r2004_v2(src: bytes, comp_size: int, decomp_size: int) -> Optional[bytes]:
    """Corrected port matching decode.c control flow exactly."""
    br = _BitReader(src, 0)
    end_comp = min(comp_size, len(src))
    dst = bytearray()
    dst_end = decomp_size

    def copy_match(comp_bytes: int, comp_offset: int) -> bool:
        src_i = len(dst) - comp_offset - 1
        if src_i < 0:
            return False
        for _ in range(comp_bytes):
            if len(dst) >= dst_end:
                return True
            if src_i < 0 or src_i >= len(dst):
                return False
            dst.append(dst[src_i])
            src_i += 1
        return True

    def take_lit(lit: int) -> bool:
        if lit <= 0:
            return True
        if br.pos + lit > len(src):
            return False
        if len(dst) + lit > dst_end:
            lit = max(0, dst_end - len(dst))
        dst.extend(src[br.pos:br.pos + lit])
        br.pos += lit
        return True

    try:
        lit, opcode1 = _read_literal_length(br)
        if not take_lit(lit):
            return None
        opcode1 = 0x00

        while br.pos < end_comp and len(dst) < dst_end:
            if opcode1 == 0x00:
                opcode1 = br.rc()

            if opcode1 >= 0x40:
                comp_bytes = ((opcode1 & 0xF0) >> 4) - 1
                opcode2 = br.rc()
                comp_offset = (opcode2 << 2) | ((opcode1 & 0x0C) >> 2)
                if opcode1 & 0x03:
                    lit = opcode1 & 0x03
                    opcode1 = 0x00
                else:
                    lit, opcode1 = _read_literal_length(br)
            elif 0x21 <= opcode1 <= 0x3F:
                comp_bytes = opcode1 - 0x1E
                comp_offset, lit = _read_two_byte_offset(br)
                if lit != 0:
                    opcode1 = 0x00
                else:
                    lit, opcode1 = _read_literal_length(br)
            elif opcode1 == 0x20:
                comp_bytes = _read_long_compression_offset(br) + 0x21
                comp_offset, lit = _read_two_byte_offset(br)
                if lit != 0:
                    opcode1 = 0x00
                else:
                    lit, opcode1 = _read_literal_length(br)
            elif 0x12 <= opcode1 <= 0x1F:
                comp_bytes = (opcode1 & 0x0F) + 2
                comp_offset, lit = _read_two_byte_offset(br)
                comp_offset += 0x3FFF
                if lit != 0:
                    opcode1 = 0x00
                else:
                    lit, opcode1 = _read_literal_length(br)
            elif opcode1 == 0x10:
                comp_bytes = _read_long_compression_offset(br) + 9
                comp_offset, lit = _read_two_byte_offset(br)
                comp_offset += 0x3FFF
                if lit != 0:
                    opcode1 = 0x00
                else:
                    lit, opcode1 = _read_literal_length(br)
            elif opcode1 == 0x11:
                break
            else:
                return None

            if not copy_match(comp_bytes, comp_offset):
                return None
            if lit and not take_lit(lit):
                return None
    except EOFError:
        return None
    return bytes(dst)


def _r2000_sections(data: bytes) -> List[Dict[str, Any]]:
    """Section locator records at 0x19 (after version+header fields)."""
    if len(data) < 0x19 + 4:
        return []
    nsec = _u32(data, 0x15)
    if nsec is None or not (0 < nsec <= 32):
        return []
    pos = 0x19
    names = [
        "AcDb:Header", "AcDb:Classes", "AcDb:Handles",
        "AcDb:ObjFreeSpace", "AcDb:Template", "AcDb:AuxHeader",
    ]
    out = []
    for j in range(nsec):
        if pos + 9 > len(data):
            break
        number = data[pos]
        addr = _u32(data, pos + 1)
        size = _u32(data, pos + 5)
        pos += 9
        if addr is None or size is None:
            break
        if addr + size > len(data) or size == 0:
            continue
        label = names[j] if j < len(names) else f"section_{number}"
        out.append({
            "offset": addr, "size": size, "label": label,
            "kind": "section", "number": number,
        })
    return out


def _r2004_sections(data: bytes) -> List[Dict[str, Any]]:
    """Decrypt R2004 header @0x80, read section page map, return page regions."""
    if len(data) < 0x80 + 0x6C:
        return []
    # Encrypted header is sizeof(Dwg_R2004_Header) — through padding[12] @0x6c
    # System section fields follow in the same struct but live on-disk after
    # the encrypted block; only the first 0x6c (+12 padding = 0x78) is encrypted.
    enc_size = 0x6C + 12  # through padding
    if 0x80 + enc_size > len(data):
        enc_size = min(0x78, len(data) - 0x80)
    dec = decrypt_r2004_header(data[0x80:0x80 + enc_size])
    if dec[:8] != b"AcFssFcA":
        # some files may have shorter check — try full
        if not dec.startswith(b"AcFssFcAJMB"):
            return []

    # Field offsets within decrypted header (from r2004_file_header.spec)
    # file_ID_string[12] @0, header_address @0x0c, header_size @0x10,
    # x04 @0x14, gaps..., last_section_id @0x28, last_section_address @0x2c (RLL),
    # secondheader @0x34 (RLL), numgaps @0x3c, numsections @0x40,
    # x20 @0x44, x80 @0x48, x40 @0x4c, section_map_id @0x50,
    # section_map_address @0x54 (RLL), section_info_id @0x5c,
    # section_array_size @0x60, gap_array_size @0x64, crc32 @0x68
    def du32(o):
        return _u32(dec, o)

    def du64(o):
        return _u64(dec, o)

    section_map_address = du64(0x54)
    section_array_size = du32(0x60)
    section_map_id = du32(0x50)
    numsections = du32(0x40)
    numgaps = du32(0x3c)
    if section_map_address is None:
        return []

    # System section at section_map_address + 0x100
    sys_off = section_map_address + 0x100
    if sys_off + 0x14 > len(data):
        # try search for magic 0x41630e3b near claimed address
        return _r2004_scan_map(data, section_map_address)

    section_type = _u32(data, sys_off)
    if section_type != 0x41630E3B:
        return _r2004_scan_map(data, section_map_address)

    decomp_data_size = _u32(data, sys_off + 4)
    comp_data_size = _u32(data, sys_off + 8)
    # compression_type @+12, checksum @+0x10 (relative to sys_off)
    # compressed payload starts at sys_off + 0x14
    if not decomp_data_size or not comp_data_size:
        return []
    if decomp_data_size > 0x2F000000 or comp_data_size > len(data):
        return []
    payload = data[sys_off + 0x14: sys_off + 0x14 + comp_data_size]
    if len(payload) < comp_data_size:
        return []
    decomp = decompress_r2004_v2(payload, comp_data_size, decomp_data_size + 1024)
    if not decomp:
        return []
    return _parse_page_map_decomp(decomp, section_array_size, section_map_id)


def _r2004_scan_map(data: bytes, section_map_address: int) -> List[Dict[str, Any]]:
    """Fallback: scan for system section magic near claimed address."""
    start = section_map_address
    if start > len(data):
        start = len(data) & 0xFFFFFF00
    # search backwards on 0x20 boundaries
    pos = start
    while pos > 0x120:
        pos -= 0x20
        if pos + 4 > len(data):
            continue
        if _u32(data, pos) == 0x41630E3B:
            decomp_size = _u32(data, pos + 4)
            comp_size = _u32(data, pos + 8)
            if not decomp_size or not comp_size or comp_size > len(data):
                continue
            payload = data[pos + 0x14: pos + 0x14 + comp_size]
            if len(payload) < comp_size:
                continue
            decomp = decompress_r2004_v2(payload, comp_size, decomp_size + 1024)
            if decomp:
                return _parse_page_map_decomp(decomp, None, None)
    return []


def _parse_page_map_decomp(
    decomp: bytes,
    section_array_size: Optional[int],
    section_map_id: Optional[int],
) -> List[Dict[str, Any]]:
    """Page map entries: (number:u32, size:u32) with addresses from 0x100."""
    out = []
    address = 0x100
    pos = 0
    while pos + 8 <= len(decomp):
        number = struct.unpack_from("<I", decomp, pos)[0]
        size = struct.unpack_from("<I", decomp, pos + 4)[0]
        pos += 8
        # negative number => gap, also consumes 16 more bytes in libredwg
        if number > 0x7FFFFFFF:
            # signed negative gap
            if pos + 16 <= len(decomp):
                pos += 16
            # gaps still advance address only if number <= section_array_size
            # libredwg: number is BITCODE_RLd — treat high bit as negative
            signed = number - 0x100000000 if number >= 0x80000000 else number
            if section_array_size is None or (signed <= section_array_size):
                if size < len(decomp) * 4:
                    address += size
            continue
        if section_array_size is not None and number > section_array_size:
            # ignored entry — does not advance address in libredwg
            continue
        if size == 0 or size > 0x10000000:
            break
        # file offset of this page = address (pages live from 0x100)
        # But system section map itself is NOT a data page — still useful
        # as mutation targets for payload.
        out.append({
            "offset": address,
            "size": size,
            "label": f"page#{number}",
            "kind": "page",
            "number": number,
        })
        address += size
        if section_array_size is not None and len(out) > section_array_size + 8:
            break
        if len(out) > 512:
            break
    # Prefer data pages over the map page itself when possible
    return out


def extract_dwg_sections(path_or_data, max_pages: int = 64) -> List[Dict[str, Any]]:
    """Return payload regions for a DWG file. Empty list if unsupported."""
    if isinstance(path_or_data, (bytes, bytearray)):
        data = bytes(path_or_data)
    else:
        with open(path_or_data, "rb") as f:
            data = f.read()
    if len(data) < 6 or data[:2] != b"AC" or not data[2:6].isdigit():
        return []
    ver = data[:6]
    try:
        if ver <= b"AC1015":
            # AC1012/AC1014/AC1015 share R13-R2000 locator layout
            secs = _r2000_sections(data)
        elif ver == b"AC1021":
            # R2007: Reed-Solomon file header — not ported yet
            secs = []
        else:
            # AC1018, AC1024, AC1027, AC1032 → R2004 path
            secs = _r2004_sections(data)
            # Prefer named section-info regions when available (richer labels)
            named = _r2004_named_sections(data)
            if named:
                secs = named + secs
    except Exception:
        return []
    # clamp + dedupe
    seen = set()
    out = []
    for s in secs:
        off, size = int(s["offset"]), int(s["size"])
        if off < 0 or size <= 0 or off >= len(data):
            continue
        size = min(size, len(data) - off)
        key = (off, size)
        if key in seen:
            continue
        seen.add(key)
        s = dict(s)
        s["offset"] = off
        s["size"] = size
        out.append(s)
        if len(out) >= max_pages:
            break
    return out


def _r2004_named_sections(data: bytes) -> List[Dict[str, Any]]:
    """Parse R2004 Section Info → named regions with file offsets.

    Section Info lives in a data section referenced by section_info_id.
    Each info entry lists pages by number; page file offsets come from the
    section page map (same as _r2004_sections).
    """
    if len(data) < 0x80 + 0x78:
        return []
    enc_size = min(0x78, len(data) - 0x80)
    dec = decrypt_r2004_header(data[0x80:0x80 + enc_size])
    if not dec.startswith(b"AcFssFcAJMB"):
        return []

    def du32(o):
        return _u32(dec, o)

    def du64(o):
        return _u64(dec, o)

    section_map_address = du64(0x54)
    section_info_id = du32(0x5c)
    section_array_size = du32(0x60)
    if section_map_address is None or section_info_id is None:
        return []

    # Page map → number → (file_offset, size)
    pages = _r2004_sections(data)
    page_by_num = {}
    for p in pages:
        page_by_num[int(p.get("number") or -1)] = (
            int(p["offset"]), int(p["size"]))

    # Locate section_info data section via page map number
    info_page = page_by_num.get(int(section_info_id))
    if not info_page:
        # scan for data-section magic 0x4163003b
        info_off = None
        for p in pages:
            o = int(p["offset"])
            if o + 4 <= len(data) and _u32(data, o) == 0x4163003B:
                info_off = o
                break
        if info_off is None:
            return []
        info_page = (info_off, int(pages[0]["size"]) if pages else 0)

    info_off, _info_sz = info_page
    if info_off + 0x14 > len(data) or _u32(data, info_off) != 0x4163003B:
        # try +0 header fields anyway
        if info_off + 12 > len(data):
            return []
    decomp_size = _u32(data, info_off + 4)
    comp_size = _u32(data, info_off + 8)
    if not decomp_size or not comp_size or comp_size > len(data):
        return []
    payload = data[info_off + 0x14: info_off + 0x14 + comp_size]
    if len(payload) < comp_size:
        return []
    decomp = decompress_r2004_v2(payload, comp_size, decomp_size + 1024)
    if not decomp or len(decomp) < 20:
        return []

    # section_infohdr: 5 x u32 = 20 bytes
    num_desc = struct.unpack_from("<I", decomp, 0)[0]
    if num_desc == 0 or num_desc > 64:
        return []
    pos = 20
    out: List[Dict[str, Any]] = []
    for _ in range(num_desc):
        if pos + 32 + 64 > len(decomp):
            break
        size = struct.unpack_from("<Q", decomp, pos)[0]
        num_sections = struct.unpack_from("<I", decomp, pos + 8)[0]
        max_decomp = struct.unpack_from("<I", decomp, pos + 12)[0]
        # +16 unknown, +20 compressed, +24 type, +28 encrypted
        name_raw = decomp[pos + 32: pos + 96]
        pos += 96
        try:
            name = name_raw.split(b"\x00", 1)[0].decode("ascii", "replace")
        except Exception:
            name = f"sec_{len(out)}"
        if num_sections > 100000 or pos + 16 * num_sections > len(decomp) + 16:
            # still try to read pages if bounds ok
            if num_sections > 4096:
                break
        pages_out = []
        for _j in range(num_sections):
            if pos + 16 > len(decomp):
                break
            pnum = struct.unpack_from("<i", decomp, pos)[0]
            psize = struct.unpack_from("<I", decomp, pos + 4)[0]
            # address u64 at pos+8 is decompressed offset within section
            pos += 16
            if pnum in page_by_num:
                foff, fsz = page_by_num[pnum]
                pages_out.append({
                    "offset": foff,
                    "size": fsz,
                    "label": f"{name}#p{pnum}",
                    "kind": "section_page",
                    "number": pnum,
                    "section": name,
                })
            elif pnum > 0:
                # page not in map — skip
                pass
        if pages_out:
            out.extend(pages_out)
        elif size and pages_out == [] and num_sections == 0:
            pass
    return out


def section_control_offsets(data: bytes) -> List[Tuple[int, int, str]]:
    """Encrypted-header + section-map control fields for directed mutation.

    Returns (offset, length, note) entries.  These steer *which* pages get
    decoded (section_map_address, sizes, ids) without needing to flip bytes
    inside a compressed payload.
    """
    out: List[Tuple[int, int, str]] = []
    if len(data) < 0x80 + 0x78:
        return out
    ver = data[:6]
    if ver <= b"AC1015":
        # R13-R2000: section locators at fixed header offsets (covered by
        # format_profiles dwg grid); nothing extra here.
        return out
    if ver == b"AC1021":
        return out  # R2007 RS header not ported

    enc_size = min(0x78, len(data) - 0x80)
    dec = decrypt_r2004_header(data[0x80:0x80 + enc_size])
    if not dec.startswith(b"AcFssFcAJMB"):
        return out

    def du32(o):
        return _u32(dec, o)

    def du64(o):
        return _u64(dec, o)

    # file offsets of the *encrypted* copies of these fields (mutation must
    # hit the ciphertext on disk).  Decrypted field @off ↔ file @0x80+off.
    fields = [
        (0x28, 4, "last_section_id"),
        (0x2c, 8, "last_section_address"),
        (0x3c, 4, "numgaps"),
        (0x40, 4, "numsections"),
        (0x50, 4, "section_map_id"),
        (0x54, 8, "section_map_address"),
        (0x5c, 4, "section_info_id"),
        (0x60, 4, "section_array_size"),
        (0x64, 4, "gap_array_size"),
    ]
    for off, sz, name in fields:
        if off + sz <= len(dec):
            out.append((0x80 + off, sz, name))

    sma = du64(0x54)
    if sma is not None:
        sys_off = sma + 0x100
        if 0 <= sys_off < len(data) and sys_off + 12 <= len(data) \
                and _u32(data, sys_off) == 0x41630E3B:
            out.append((sys_off + 4, 4, "secmap.decomp_data_size"))
            out.append((sys_off + 8, 4, "secmap.comp_data_size"))
            out.append((sys_off + 12, 4, "secmap.compression_type"))
    return out


def sample_offsets(
    regions: List[Dict[str, Any]],
    per_region: int = 3,
    value_size: int = 4,
) -> List[Tuple[int, int, str]]:
    """Sample (offset, length, label) candidates inside regions."""
    out: List[Tuple[int, int, str]] = []
    for r in regions:
        off, size = int(r["offset"]), int(r["size"])
        label = r.get("label") or r.get("kind") or "sec"
        if size <= value_size:
            if size > 0:
                out.append((off, size, label))
            continue
        # head / mid / tail samples
        positions = [off, off + (size // 2), off + max(0, size - value_size)]
        # also a quarter point for larger regions
        if size > value_size * 8:
            positions.insert(1, off + size // 4)
        for p in positions:
            if p < off or p + value_size > off + size:
                continue
            out.append((p, value_size, label))
            if len([x for x in out if x[2] == label]) >= per_region:
                break
    # dedupe by offset
    seen = set()
    uniq = []
    for o, ln, lab in out:
        if o in seen:
            continue
        seen.add(o)
        uniq.append((o, ln, lab))
    return uniq


if __name__ == "__main__":
    import sys
    for p in sys.argv[1:]:
        regs = extract_dwg_sections(p)
        print(f"{p}: {len(regs)} regions")
        for r in regs[:20]:
            print(f"  {r['offset']:#08x} +{r['size']:<8} {r['label']}")
        samples = sample_offsets(regs)
        print(f"  samples: {len(samples)} -> {samples[:8]}")
