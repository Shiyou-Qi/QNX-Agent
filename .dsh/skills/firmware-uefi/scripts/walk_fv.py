#!/usr/bin/env python3
"""Qi-NX-Agent (Firmware / UEFI): structured Firmware Volume / FFS / section walker.

Usage:
    python walk_fv.py <image> [--json] [--extract DIR] [--max-files N]

This is the authoritative walker of the Qi-NX firmware toolkit: it parses the
PI spec structures directly (no external dependency), so it works on an air-gapped
host. `uefi_walk.py` remains available as a coarser fallback.

What it parses, per the UEFI PI specification:
  * EFI_FIRMWARE_VOLUME_HEADER  — FvLength at +0x20, HeaderLength at +0x30,
    FileSystemGuid at +0x10, Revision at +0x37, Attributes at +0x2C.
  * EFI_FFS_FILE_HEADER (0x18) and EFI_FFS_FILE_HEADER2 (0x20, when the 3-byte
    Size field is 0xFFFFFF and ExtendedSize at +0x18 applies).
  * EFI_COMMON_SECTION_HEADER (4) and ...HEADER2 (8, same 0xFFFFFF escape).

Known limitation: compressed (EFI_SECTION_COMPRESSION) and GUID-defined
(EFI_SECTION_GUID_DEFINED) sections are reported but not decompressed. Point
UEFIExtract at the image to obtain decompressed payloads, then re-run this
walker or `lief_info.py` on the extracted PE32/TE files.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BANNER = "by Qi-NX-Agent (Copyright Qi-NX)"

FV_SIGNATURE = b"_FVH"
FV_SIG_OFFSET = 0x28           # "_FVH" sits at header + 0x28

FFS_HEADER_SIZE = 0x18
FFS_HEADER2_SIZE = 0x20
FFS_LARGE_SIZE = 0xFFFFFF

SECTION_HEADER_SIZE = 0x04
SECTION_HEADER2_SIZE = 0x08
SECTION_LARGE_SIZE = 0xFFFFFF

# EFI_FV_FILETYPE_* (PI spec). Keys are exact spec values.
FILE_TYPES = {
    0x00: "RAW",
    0x01: "FREEFORM",
    0x02: "SECURITY_CORE",
    0x03: "PEI_CORE",
    0x04: "DXE_CORE",
    0x05: "PEIM",
    0x06: "DRIVER",
    0x07: "COMBINED_PEIM_DRIVER",
    0x08: "APPLICATION",
    0x09: "MM",                      # formerly EFI_FV_FILETYPE_SMM
    0x0A: "FIRMWARE_VOLUME_IMAGE",
    0x0B: "COMBINED_MM_DXE",
    0x0C: "MM_CORE",
    0x0D: "MM_STANDALONE",
    0x0E: "MM_CORE_STANDALONE",
    0xF0: "FFS_PAD",
}

# EFI_SECTION_* (PI spec). Keys are exact spec values.
SECTION_TYPES = {
    0x01: "COMPRESSION",
    0x02: "GUID_DEFINED",
    0x03: "DISPOSABLE",
    0x10: "PE32",
    0x11: "PIC",
    0x12: "TE",
    0x13: "DXE_DEPEX",
    0x14: "VERSION",
    0x15: "USER_INTERFACE",
    0x16: "COMPATIBILITY16",
    0x17: "FIRMWARE_VOLUME_IMAGE",
    0x18: "FREEFORM_SUBTYPE_GUID",
    0x19: "RAW",
    0x1B: "PEI_DEPEX",
    0x1C: "SMM_DEPEX",
}

# MM/SMM modules worth flagging for a Ring -2 review.
SMM_FILE_TYPES = {0x09, 0x0B, 0x0C, 0x0D, 0x0E}

EXTRACTABLE_SECTIONS = {0x10: "pe32", 0x12: "te"}

COMPRESSION_KINDS = {0x00: "not-compressed", 0x01: "EFI-standard", 0x02: "custom/LZMA"}


def _u16(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 2], "little")


def _u24(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 3], "little")


def _u32(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 4], "little")


def _u64(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 8], "little")


def _guid(b: bytes, o: int) -> str:
    d1, d2, d3 = _u32(b, o), _u16(b, o + 4), _u16(b, o + 6)
    tail = b[o + 8:o + 16].hex()
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{tail[:4]}-{tail[4:]}"


def file_type_name(t: int) -> str:
    return FILE_TYPES.get(t, f"UNKNOWN(0x{t:02x})")


def section_type_name(t: int) -> str:
    return SECTION_TYPES.get(t, f"UNKNOWN(0x{t:02x})")


def iter_firmware_volumes(data: bytes):
    """Yield firmware volumes found by scanning for the `_FVH` signature."""
    idx = 0
    while True:
        i = data.find(FV_SIGNATURE, idx)
        if i < 0:
            return
        hdr = i - FV_SIG_OFFSET
        if hdr < 0 or hdr + 0x38 > len(data):
            idx = i + 4
            continue
        fv_len = _u64(data, hdr + 0x20)
        hdr_len = _u16(data, hdr + 0x30)
        if (fv_len < 0x38 or hdr + fv_len > len(data)
                or not 0x38 <= hdr_len <= fv_len):
            idx = i + 4
            continue
        yield {
            "offset": hdr,
            "length": fv_len,
            "header_length": hdr_len,
            "file_system_guid": _guid(data, hdr + 0x10),
            "revision": data[hdr + 0x37],
            "attributes": _u32(data, hdr + 0x2C),
        }
        idx = hdr + fv_len


def iter_ffs_files(data: bytes, fv_off: int, fv_len: int, fv_hdr_len: int):
    """Walk the FFS files inside one firmware volume."""
    pos = fv_off + fv_hdr_len
    end = min(fv_off + fv_len, len(data))
    while pos + FFS_HEADER_SIZE <= end:
        # Erased/blank flash or free space terminates the walkable region.
        if data[pos:pos + 16] == b"\xff" * 16:
            return
        size = _u24(data, pos + 0x14)
        hdr_size = FFS_HEADER_SIZE
        if size == FFS_LARGE_SIZE:
            if pos + FFS_HEADER2_SIZE > end:
                return
            size = _u64(data, pos + 0x18)
            hdr_size = FFS_HEADER2_SIZE
        if size < hdr_size or pos + size > end:
            # Misaligned; advance one alignment unit and retry.
            pos = (pos + 8) & ~7
            continue
        yield {
            "offset": pos,
            "size": size,
            "header_size": hdr_size,
            "guid": _guid(data, pos),
            "type": data[pos + 0x12],
            "type_name": file_type_name(data[pos + 0x12]),
            "attributes": data[pos + 0x13],
            "state": data[pos + 0x17],
            "is_smm": data[pos + 0x12] in SMM_FILE_TYPES,
        }
        pos = (pos + size + 7) & ~7


def iter_sections(data: bytes, start: int, end: int):
    """Walk the sections of one FFS file body (sections are 4-byte aligned)."""
    pos = start
    while pos + SECTION_HEADER_SIZE <= end:
        size = _u24(data, pos)
        stype = data[pos + 3]
        hdr_size = SECTION_HEADER_SIZE
        if size == SECTION_LARGE_SIZE:
            if pos + SECTION_HEADER2_SIZE > end:
                return
            size = _u32(data, pos + 4)
            hdr_size = SECTION_HEADER2_SIZE
        if size < hdr_size or pos + size > end:
            return
        payload_off = pos + hdr_size
        payload_len = size - hdr_size
        entry = {
            "offset": pos,
            "size": size,
            "header_size": hdr_size,
            "type": stype,
            "type_name": section_type_name(stype),
            "payload_offset": payload_off,
            "payload_size": payload_len,
        }
        if stype == 0x01 and payload_len >= 5:
            entry["uncompressed_size"] = _u32(data, payload_off)
            entry["compression_kind"] = COMPRESSION_KINDS.get(
                data[payload_off + 4], f"unknown(0x{data[payload_off + 4]:02x})")
            entry["needs_decompression"] = True
        if stype == 0x02 and payload_len >= 16:
            entry["section_definition_guid"] = _guid(data, payload_off)
            entry["needs_decompression"] = True
        yield entry
        pos = (pos + size + 3) & ~3


def walk(image_path: str | Path, extract_dir: str | Path | None = None,
         max_files: int = 100000) -> dict:
    """Return the full FV/FFS/section inventory, optionally extracting PE32/TE."""
    path = Path(image_path)
    data = path.read_bytes()

    result: dict = {
        "tool": "qi-nx-walk-fv",
        "author": "Qi-NX",
        "image": str(path),
        "size": len(data),
        "firmware_volumes": [],
        "file_total": 0,
        "smm_file_total": 0,
        "section_total": 0,
        "extracted": [],
        "notes": [],
    }

    out_root = Path(extract_dir) if extract_dir else None
    if out_root:
        out_root.mkdir(parents=True, exist_ok=True)

    for fv_index, fv in enumerate(iter_firmware_volumes(data)):
        fv_entry = dict(fv)
        fv_entry["offset"] = hex(fv["offset"])
        fv_entry["files"] = []

        for ffs in iter_ffs_files(data, fv["offset"], fv["length"], fv["header_length"]):
            if result["file_total"] >= max_files:
                result["notes"].append(f"stopped after max_files={max_files}")
                break
            result["file_total"] += 1
            if ffs["is_smm"]:
                result["smm_file_total"] += 1

            body_start = ffs["offset"] + ffs["header_size"]
            body_end = ffs["offset"] + ffs["size"]

            sections = []
            for sec in iter_sections(data, body_start, body_end):
                result["section_total"] += 1
                sec_entry = dict(sec)
                sec_entry["offset"] = hex(sec["offset"])
                sec_entry["payload_offset"] = hex(sec["payload_offset"])
                sections.append(sec_entry)

                ext = EXTRACTABLE_SECTIONS.get(sec["type"])
                if out_root and ext:
                    payload = data[sec["payload_offset"]:
                                   sec["payload_offset"] + sec["payload_size"]]
                    dest_dir = out_root / f"fv{fv_index:02d}_{fv['offset']:#x}"
                    dest_dir.mkdir(parents=True, exist_ok=True)
                    dest = dest_dir / f"{ffs['guid']}.{ext}"
                    dest.write_bytes(payload)
                    result["extracted"].append({
                        "path": str(dest),
                        "section_type": sec["type_name"],
                        "source_offset": hex(sec["payload_offset"]),
                        "size": len(payload),
                    })

            fv_entry["files"].append({
                "offset": hex(ffs["offset"]),
                "size": ffs["size"],
                "guid": ffs["guid"],
                "type": ffs["type"],
                "type_name": ffs["type_name"],
                "attributes": ffs["attributes"],
                "state": ffs["state"],
                "is_smm": ffs["is_smm"],
                "sections": sections,
            })
        result["firmware_volumes"].append(fv_entry)

    if not result["firmware_volumes"]:
        result["notes"].append(
            "no valid firmware volume found — the image may be a capsule, a raw "
            "flash dump with an offset BIOS region, or compressed; try binwalk "
            "or carve the BIOS region first")

    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--extract", help="directory to write PE32/TE sections into")
    ap.add_argument("--max-files", type=int, default=100000)
    args = ap.parse_args()

    path = Path(args.image)
    if not path.is_file():
        print(f"not a file: {path}", file=sys.stderr)
        return 2

    info = walk(path, args.extract, args.max_files)

    if args.json:
        print(json.dumps(info, indent=2))
        return 0

    print(f"# walk_fv — {info['image']}")
    print(f"# {BANNER}")
    print(f"size={info['size']} FVs={len(info['firmware_volumes'])} "
          f"files={info['file_total']} sections={info['section_total']} "
          f"smm_files={info['smm_file_total']}")
    for fv in info["firmware_volumes"]:
        print(f"\nFV @ {fv['offset']} size={fv['length']} hdr={fv['header_length']} "
              f"fs_guid={fv['file_system_guid']} rev={fv['revision']}")
        for f in fv["files"]:
            flag = " [SMM]" if f["is_smm"] else ""
            print(f"  {f['guid']}  {f['type_name']:22} size=0x{f['size']:x} "
                  f"@{f['offset']}{flag}")
            for s in f["sections"]:
                extra = ""
                if s.get("needs_decompression"):
                    extra = (f" -> {s.get('compression_kind', 'guid-defined')} "
                             f"uncompressed={s.get('uncompressed_size', '?')}")
                print(f"      {s['type_name']:22} size=0x{s['size']:x} "
                      f"payload@{s['payload_offset']}{extra}")
    for note in info["notes"]:
        print(f"\nnote: {note}")
    if info["extracted"]:
        print(f"\nextracted {len(info['extracted'])} section(s):")
        for e in info["extracted"][:40]:
            print(f"  {e['path']} ({e['section_type']}, {e['size']} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
