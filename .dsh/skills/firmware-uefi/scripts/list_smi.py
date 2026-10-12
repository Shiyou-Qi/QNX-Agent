#!/usr/bin/env python3
"""Qi-NX-Agent (Firmware / UEFI): enumerate SMM / MM modules and dispatch surface.

Usage:
    python list_smi.py <image-or-module> [--json] [--guids guids.csv]
                       [--extract DIR] [--include-dxe]

Input may be a full firmware image (FFS types are used to find Ring -2 modules)
or a single extracted PE32/TE module (the whole file is treated as one module).

What it reports, per module:
  * FFS identity: GUID, type (EFI_FV_FILETYPE_MM / MM_CORE / MM_STANDALONE /
    COMBINED_MM_DXE), size, file offset.
  * SMM dispatch / communication markers found as ASCII and UTF-16 strings,
    with their offsets. These are EDK2 symbol and protocol *names*, which is
    reliable evidence that a module participates in SMM dispatch.
  * With `--guids`, whether any GUID from an authoritative list is referenced
    by the module bytes (wire-format search).

Design note — why no hardcoded GUIDs: an incorrect GUID constant silently
produces false negatives, which is worse than no check at all. Supply
UEFITool's `guids.csv` (Name,GUID per line) via `--guids` and the search becomes
authoritative. Without it, this tool still delivers the FFS-type and
string-marker evidence.

This is a triage enumerator, not a disassembler: it does not recover SwSmi
handler input values. Use the reported module list with IDA/Ghidra and
`gEfiSmmSwDispatch2ProtocolGuid` cross-references for the handler table.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BANNER = "by Qi-NX-Agent (Copyright Qi-NX)"

# EDK2 / PI names that evidence SMM participation. Searched as ASCII and UTF-16LE.
SMM_MARKERS = (
    # SwSmi dispatch
    "EFI_SMM_SW_DISPATCH2_PROTOCOL",
    "gEfiSmmSwDispatch2ProtocolGuid",
    "EFI_MM_SW_DISPATCH2_PROTOCOL",
    "gEfiMmSwDispatch2ProtocolGuid",
    "SmmSwDispatch2",
    "SwSmiInputValue",
    "SmiHandler",
    # Core / access / CPU
    "EFI_SMM_BASE2_PROTOCOL",
    "gEfiSmmBase2ProtocolGuid",
    "EFI_SMM_ACCESS2_PROTOCOL",
    "gEfiSmmAccess2ProtocolGuid",
    "gEfiSmmCpuProtocolGuid",
    "EFI_SMM_SYSTEM_TABLE2",
    "SmmCorePrivate",
    "gSmmCorePrivate",
    # Communication / buffer validation
    "EFI_SMM_COMMUNICATION_PROTOCOL",
    "gEfiSmmCommunicationProtocolGuid",
    "CommBuffer",
    "SmmIsBufferOutsideSmmValid",
    "SmmCommunication",
    # Chipset / device dispatch families
    "gEfiSmmIchnDispatchProtocolGuid",
    "gEfiSmmPeriodicTimerDispatch2ProtocolGuid",
    "gEfiSmmPowerButtonDispatch2ProtocolGuid",
    "gEfiSmmStandbyButtonDispatch2ProtocolGuid",
    "gEfiSmmGpiDispatch2ProtocolGuid",
    "gEfiSmmUsbDispatch2ProtocolGuid",
    "gEfiSmmStatusCodeProtocolGuid",
    # Entry / init
    "PiSmmCpuDxeSmm",
    "SmiEntry",
    "SmmInit",
    "SmmAccess",
)

SMM_FFS_TYPES = {0x09, 0x0B, 0x0C, 0x0D, 0x0E}
SMM_FFS_TYPE_NAMES = {
    0x09: "MM", 0x0B: "COMBINED_MM_DXE", 0x0C: "MM_CORE",
    0x0D: "MM_STANDALONE", 0x0E: "MM_CORE_STANDALONE",
}


def _load_walk_fv():
    try:
        import walk_fv  # type: ignore
        return walk_fv
    except Exception:
        return None


def find_markers(data: bytes, markers=SMM_MARKERS) -> list[dict]:
    """Locate ASCII and UTF-16LE occurrences of the SMM marker strings."""
    hits: list[dict] = []
    for name in markers:
        ascii_bytes = name.encode("ascii")
        utf16_bytes = name.encode("utf-16-le")
        for encoding, needle in (("ascii", ascii_bytes), ("utf16le", utf16_bytes)):
            idx = 0
            while True:
                i = data.find(needle, idx)
                if i < 0:
                    break
                hits.append({"marker": name, "encoding": encoding, "offset": i})
                idx = i + 1
    hits.sort(key=lambda h: (h["offset"], h["marker"]))
    return hits


def guid_to_wire(canonical: str) -> bytes | None:
    """Convert a canonical GUID string to UEFI wire format (mixed-endian)."""
    try:
        parts = canonical.strip().strip("{}").split("-")
        if len(parts) != 5:
            return None
        d1 = int(parts[0], 16)
        d2 = int(parts[1], 16)
        d3 = int(parts[2], 16)
        tail = bytes.fromhex(parts[3] + parts[4])
        if len(tail) != 8:
            return None
        return (d1.to_bytes(4, "little") + d2.to_bytes(2, "little")
                + d3.to_bytes(2, "little") + tail)
    except Exception:
        return None


def load_guids(guids_path: str | Path) -> dict[str, bytes]:
    """Parse `Name,GUID` CSV lines into {name: wire_bytes}."""
    table: dict[str, bytes] = {}
    text = Path(guids_path).read_text(errors="replace")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "," in line:
            name, _, guid = line.partition(",")
        else:
            name, guid = "", line
        wire = guid_to_wire(guid)
        if wire is None:
            continue
        key = name.strip() or guid.strip()
        table[key] = wire
    return table


def find_guid_refs(data: bytes, guid_table: dict[str, bytes]) -> list[dict]:
    hits: list[dict] = []
    for name, wire in guid_table.items():
        idx = 0
        while True:
            i = data.find(wire, idx)
            if i < 0:
                break
            hits.append({"guid_name": name, "offset": i})
            idx = i + 1
    hits.sort(key=lambda h: h["offset"])
    return hits


def _analyse_module(name: str, data: bytes, base_offset: int,
                    guid_table: dict[str, bytes] | None) -> dict:
    markers = find_markers(data)
    entry = {
        "name": name,
        "size": len(data),
        "markers": [{"marker": m["marker"], "encoding": m["encoding"],
                     "offset": hex(base_offset + m["offset"])} for m in markers],
        "marker_names": sorted({m["marker"] for m in markers}),
    }
    if guid_table:
        refs = find_guid_refs(data, guid_table)
        entry["guid_refs"] = [{"guid_name": r["guid_name"],
                               "offset": hex(base_offset + r["offset"])}
                              for r in refs]
    return entry


def list_smm(image_path: str | Path, guids_path: str | Path | None = None,
             extract_dir: str | Path | None = None,
             include_dxe: bool = False) -> dict:
    """Enumerate SMM/MM modules in an image (or analyse one module file)."""
    path = Path(image_path)
    data = path.read_bytes()
    guid_table = load_guids(guids_path) if guids_path else None

    result: dict = {
        "tool": "qi-nx-list-smi",
        "author": "Qi-NX",
        "image": str(path),
        "size": len(data),
        "mode": None,
        "modules": [],
        "notes": [],
    }
    if guid_table is not None:
        result["guid_table_entries"] = len(guid_table)

    walk_fv = _load_walk_fv()
    out_root = Path(extract_dir) if extract_dir else None
    if out_root:
        out_root.mkdir(parents=True, exist_ok=True)

    found_ffs = False
    if walk_fv is not None:
        for fv in walk_fv.iter_firmware_volumes(data):
            for ffs in walk_fv.iter_ffs_files(data, fv["offset"], fv["length"],
                                              fv["header_length"]):
                found_ffs = True
                is_smm_type = ffs["type"] in SMM_FFS_TYPES
                body_start = ffs["offset"] + ffs["header_size"]
                body_end = min(ffs["offset"] + ffs["size"], len(data))
                body = data[body_start:body_end]
                analysed = _analyse_module(ffs["guid"], body, body_start, guid_table)
                # Keep a module if its FFS type says SMM, or it evidences dispatch.
                if not (is_smm_type or analysed["marker_names"]):
                    continue
                if not is_smm_type and not include_dxe:
                    # A DXE driver referencing SMM names is a lead, not an SMM
                    # module; include it only on request.
                    continue
                analysed.update({
                    "guid": ffs["guid"],
                    "ffs_type": ffs["type"],
                    "ffs_type_name": ffs["type_name"],
                    "is_smm_ffs_type": is_smm_type,
                    "file_offset": hex(ffs["offset"]),
                })
                if out_root and is_smm_type:
                    dest = out_root / f"{ffs['guid']}.bin"
                    dest.write_bytes(body)
                    analysed["extracted_path"] = str(dest)
                result["modules"].append(analysed)

    if not found_ffs:
        # Single-module mode (extracted PE32/TE) or a non-FV container.
        analysed = _analyse_module(path.name, data, 0, guid_table)
        analysed.update({
            "guid": None,
            "ffs_type": None,
            "ffs_type_name": "single-module",
            "is_smm_ffs_type": None,
            "file_offset": "0x0",
        })
        result["modules"].append(analysed)
        result["mode"] = "single-module"
        result["notes"].append(
            "no firmware volume found; analysed the whole file as one module")
    else:
        result["mode"] = "firmware-image"
        if not result["modules"]:
            result["notes"].append(
                "no MM/SMM modules found; if the image is compressed or the "
                "BIOS region is offset, carve it first, or pass --include-dxe "
                "to see DXE drivers that merely reference SMM names")

    if not result["modules"] and result["mode"] == "single-module":
        result["notes"].append("no SMM markers found in this module")

    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target", help="firmware image or an extracted PE32/TE module")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--guids", help="authoritative Name,GUID CSV (e.g. UEFITool guids.csv)")
    ap.add_argument("--extract", help="directory to write SMM module bodies into")
    ap.add_argument("--include-dxe", action="store_true",
                    help="also list non-SMM modules that reference SMM names")
    args = ap.parse_args()

    path = Path(args.target)
    if not path.is_file():
        print(f"not a file: {path}", file=sys.stderr)
        return 2

    info = list_smm(path, args.guids, args.extract, args.include_dxe)

    if args.json:
        print(json.dumps(info, indent=2))
        return 0

    print(f"# list_smi — {info['image']}")
    print(f"# {BANNER}")
    print(f"mode={info['mode']} size={info['size']} modules={len(info['modules'])}")
    for m in info["modules"]:
        kind = m.get("ffs_type_name") or "?"
        print(f"\n  {m.get('guid') or m['name']}  type={kind} "
              f"size=0x{m['size']:x} @{m.get('file_offset')}")
        if m.get("is_smm_ffs_type"):
            print("    [SMM FFS type]")
        for name in m["marker_names"]:
            hits = [h for h in m["markers"] if h["marker"] == name]
            locs = ", ".join(h["offset"] for h in hits[:4])
            print(f"    {name}  ({len(hits)} hit(s): {locs})")
        for ref in m.get("guid_refs", [])[:16]:
            print(f"    GUID {ref['guid_name']} @ {ref['offset']}")
        if m.get("extracted_path"):
            print(f"    extracted -> {m['extracted_path']}")
    for note in info["notes"]:
        print(f"\nnote: {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
