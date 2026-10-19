#!/usr/bin/env python3
"""QNX-Agent (Firmware / UEFI): walk a UEFI flash image and inventory FVs/FFSs.

Usage:
    python uefi_walk.py <bios.bin> [--json] [--guids] [--extract DIR]

Behaviour:
  * Uses `uefi_firmware` (LSVD / uefi-firmware-parser) if installed; otherwise
    falls back to a coarse UEFI Volume scan by walking the FVB header magic.
  * Always prints the banner `# by QNX-Agent (© Qi-NX)`.
  * `--extract DIR` will write each PE32/TE section as
    `<DIR>/fvNN_<FV_OFFSET>/<FFS_GUID>_ffs_<FFS_OFFSET>_sec_<N>.pe32` for follow-up
    lief_info / yara_scan. Extraction uses the PI-aware `walk_fv` implementation.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import struct
import sys
from pathlib import Path

BANNER = "by QNX-Agent (Copyright Qi-NX)"
FVH_SIGNATURE = b"_FVH"
FFS_GUID_RE = re.compile(rb"^[0-9a-fA-F\-]{32,}")
EFI_COMPRESSION_NONE = 0x00
EFI_COMPRESSION_PI_STD = 0x01
EFI_COMPRESSION_PI_CUSTOM = 0x02


def _read_u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def _read_u64(buf: bytes, off: int) -> int:
    return struct.unpack_from("<Q", buf, off)[0]


def _iter_fvs_coarse(data: bytes):
    """Yield (offset, total_size) of each FV by scanning for _FVH magic."""
    idx = 0
    while True:
        i = data.find(FVH_SIGNATURE, idx)
        if i < 0:
            return
        # FVH offset points to "Signature" field, header starts 0x28 bytes earlier
        header_off = i - 0x28
        if header_off < 0:
            idx = i + 4
            continue
        try:
            fv_length = _read_u64(data, header_off + 0x20)
        except Exception:
            idx = i + 4
            continue
        if fv_length == 0 or fv_length > len(data):
            idx = i + 4
            continue
        yield (header_off, fv_length)
        # Keep looking inside the current FV: an FV_IMAGE section can contain
        # another FV, and skipping to the outer end hides that child volume.
        idx = i + len(FVH_SIGNATURE)


def _parse_ffs_from_fv(fv_data: bytes, fv_off: int):
    """Naive FFS walk: scan for FFS file header (24 bytes) after FV header.

    This is intentionally heuristic — a real parser (uefi_firmware) is preferred
    when available. We identify FFS headers via the integrity-check byte pair
    and a sane size field, then step by `Size` aligned to 8.
    """
    offset = 0x38  # typical end of FVH for simple images
    found = 0
    while offset + 0x18 < len(fv_data) and found < 4096:
        # FFS header: Name GUID(16) IntegrityCheck(2) Type(1) Attributes(1) Size(3) State(1)
        header = fv_data[offset:offset + 0x18]
        if len(header) < 0x18:
            break
        size_triple = header[0x14:0x17]
        size = size_triple[0] | (size_triple[1] << 8) | (size_triple[2] << 16)
        if size < 0x18 or offset + size > len(fv_data):
            offset += 8
            continue
        guid = header[0:16].hex()
        ftype = header[0x12]
        state = header[0x17]
        yield {
            "guid": guid,
            "type": ftype,
            "state": state,
            "size": size,
            "offset_in_fv": offset,
            "abs_offset": fv_off + offset,
        }
        found += 1
        # FFS files are 8-byte aligned
        offset += (size + 7) & ~7


def _ffs_type_name(t: int) -> str:
    """Return the PI-spec FFS file type name.

    Delegates to `walk_fv`'s table (the authoritative one) when importable so the
    two walkers can never disagree.
    """
    try:
        import walk_fv  # type: ignore
        return walk_fv.file_type_name(t)
    except Exception:
        pass
    return {
        0x00: "RAW",
        0x01: "FREEFORM",
        0x02: "SECURITY_CORE",
        0x03: "PEI_CORE",
        0x04: "DXE_CORE",
        0x05: "PEIM",
        0x06: "DRIVER",
        0x07: "COMBINED_PEIM_DRIVER",
        0x08: "APPLICATION",
        0x09: "MM",
        0x0A: "FIRMWARE_VOLUME_IMAGE",
        0x0B: "COMBINED_MM_DXE",
        0x0C: "MM_CORE",
        0x0D: "MM_STANDALONE",
        0x0E: "MM_CORE_STANDALONE",
        0xF0: "FFS_PAD",
    }.get(t, f"UNKNOWN(0x{t:02x})")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image", help="SPI / capsule / FV binary")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--guids", action="store_true", help="also list unique GUIDs")
    ap.add_argument("--extract", help="extract every PE32/TE section to DIR")
    args = ap.parse_args()

    image = Path(args.image)
    if not image.is_file():
        print(f"not a file: {image}", file=sys.stderr)
        return 2

    data = image.read_bytes()

    out: dict = {
        "tool": "qi-nx-uefi-walk",
        "author": "Qi-NX",
        "image": str(image),
        "size": len(data),
        "fvs": [],
        "ffs_total": 0,
    }

    # Try uefi_firmware first
    fv_iter = None
    try:
        from uefi_firmware import AutoParser  # type: ignore
        parser = AutoParser(str(image))
        fv_iter = parser.parse()
    except Exception:
        fv_iter = None

    extracted_root: Path | None = None
    if args.extract:
        extracted_root = Path(args.extract)
        extracted_root.mkdir(parents=True, exist_ok=True)
        # Keep extraction consistent with the PI-aware implementation instead
        # of silently accepting --extract without writing any payloads.
        try:
            import walk_fv  # type: ignore
            walk_fv.walk(image, extracted_root)
        except Exception as exc:
            out.setdefault("notes", []).append(f"section extraction failed: {exc}")

    if fv_iter is not None:
        # uefi_firmware path
        for obj in fv_iter.iterate_objects():
            kind = obj.get("type", "")
            if kind == "FirmwareVolume":
                out["fvs"].append({
                    "offset": hex(obj.get("offset", 0)),
                    "size": hex(obj.get("size", 0)),
                    "name": obj.get("guid", "?"),
                })
            elif kind == "FirmwareFile":
                ffs_entry = {
                    "guid": obj.get("guid", "?"),
                    "type": obj.get("type_num", -1),
                    "type_name": obj.get("type_name", "?"),
                    "size": obj.get("size", 0),
                    "abs_offset": obj.get("offset", 0),
                }
                out["fvs"].append({"ffs": ffs_entry})
                out["ffs_total"] += 1
    else:
        # Coarse scan fallback
        for fv_off, fv_len in _iter_fvs_coarse(data):
            fv = {"offset": hex(fv_off), "size": hex(fv_len), "ffs": []}
            fv_data = data[fv_off:fv_off + fv_len]
            for ffs in _parse_ffs_from_fv(fv_data, fv_off):
                ffs_entry = {
                    "guid": ffs["guid"],
                    "type": ffs["type"],
                    "type_name": _ffs_type_name(ffs["type"]),
                    "size": ffs["size"],
                    "abs_offset": ffs["abs_offset"],
                }
                fv["ffs"].append(ffs_entry)
                out["ffs_total"] += 1
            out["fvs"].append(fv)

    if args.json:
        print(json.dumps(out, indent=2))
        return 0

    print(f"# uefi_walk — {image}")
    print(f"# {BANNER}")
    print(f"size: {out['size']} bytes, FVs: {len(out['fvs'])}, FFS total: {out['ffs_total']}")
    for fv in out["fvs"]:
        if "ffs" in fv and isinstance(fv["ffs"], list):
            print(f"\nFV @ {fv['offset']} size={fv['size']} ffs={len(fv['ffs'])}")
            for f in fv["ffs"][:64]:
                print(f"  {f['guid']}  type={f['type_name']:24} "
                      f"size=0x{f['size']:x} @0x{f['abs_offset']:x}")
        elif "ffs" in fv and isinstance(fv["ffs"], dict):
            f = fv["ffs"]
            print(f"  FFS {f['guid']} type={f.get('type_name','?')} size=0x{f['size']:x} @0x{f['abs_offset']:x}")
        else:
            print(f"FV @ {fv.get('offset','?')} size={fv.get('size','?')}")

    if args.guids:
        guids = set()
        for fv in out["fvs"]:
            entries = fv.get("ffs") if isinstance(fv.get("ffs"), list) else ([fv.get("ffs")] if fv.get("ffs") else [])
            for f in entries:
                if f:
                    guids.add(f["guid"])
        print(f"\nunique FFS GUIDs: {len(guids)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
