#!/usr/bin/env python3
"""Qi-NX-Agent (Firmware / UEFI): carve UEFI variable stores (NVRAM) out of an image.

Usage:
    python extract_vss.py <image> --out DIR [--json] [--size BYTES] [--raw-scan]

Why a separate tool from `vss_parse.py`: the variable store is usually buried
inside an FFS file (often inside a compressed section), so it must be located
and carved before it can be interpreted. This tool does the location + carving
and *validates* each candidate, then `vss_parse.py` parses the carved blob.

Detection is heuristic by design; every candidate records its `reason` so you can
judge it:

  1. `ffs-body`     — an FFS file body that walks as a variable store.
  2. `marker`       — a raw `_VSS` / `_VSS2` ASCII marker occurrence.
  3. `var-headers`  — a region with a plausible run of 0x55AA variable headers.

Validation counts how many well-formed variable headers a candidate contains;
a real store has several. Candidates are still written when validation is weak,
but are labelled `confidence: low` rather than silently dropped.

Note: GUID constants are deliberately NOT hardcoded — supply an authoritative
`--guids` list (for example UEFITool's `guids.csv`) when you need GUID-level
attribution. See `list_smi.py`, which accepts the same option.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BANNER = "by Qi-NX-Agent (Copyright Qi-NX)"

START_ID = 0x55AA               # EDK2 variable header StartId
VSS_MARKERS = (b"_VSS", b"_VSS2", b"_VSS3")
DEFAULT_CARVE_SIZE = 0x40000    # 256 KiB covers typical NVRAM stores
MAX_VARIABLE_HEADER = 1024      # sanity bound for a single variable name/size
MIN_VARIABLES = 2               # a real store holds several variables

# The EDK2 variable store header sits *before* the first variable header:
#   signature GUID(16) + Size(4) + Format(1) + State(1) + Reserved(2) + Reserved1(4)
# = 28 bytes, padded to 32 in FFS storage. Real images vary, so probe the
# plausible prefix lengths rather than assuming one.
STORE_HEADER_PROBES = (0x20, 0x1C, 0x18, 0x10, 0x00)


def _load_walk_fv():
    """Import the sibling walk_fv module (same directory)."""
    try:
        import walk_fv  # type: ignore
        return walk_fv
    except Exception:
        return None


ATTR_BITS = {
    0x00000001: "NV",
    0x00000002: "BS",
    0x00000004: "RT",
    0x00000008: "HW_ERR",
    0x00000010: "AUTH",
    0x00000020: "TIME_AUTH",
    0x00000040: "APPEND",
    0x00000080: "ENH_AUTH",
}

SENSITIVE_NAMES = {
    "BootOrder", "BootCurrent", "BootNext", "DriverOrder",
    "SecureBoot", "SecureBootEnable", "SetupMode", "CustomMode", "VendorKeys",
    "PK", "KEK", "db", "dbx", "dbt", "dbr",
    "OsIndications", "OsIndicationsSupported", "SignatureSupport",
    "Setup", "MeSetup", "SaSetup", "PchSetup", "CpuSetup", "AmtSetup",
}


def _guid_at(b: bytes, o: int) -> str:
    d1 = int.from_bytes(b[o:o + 4], "little")
    d2 = int.from_bytes(b[o + 4:o + 6], "little")
    d3 = int.from_bytes(b[o + 6:o + 8], "little")
    tail = b[o + 8:o + 16].hex()
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{tail[:4]}-{tail[4:]}"


def attr_names(attrs: int) -> list[str]:
    return [name for bit, name in ATTR_BITS.items() if attrs & bit]


def iter_variables(data: bytes, start: int, limit: int):
    """Yield decoded variable records from a store, starting at `start`.

    Single source of truth for EDK2 variable-header layout, shared by
    `count_variable_headers` (here), `vss_parse.py`, and the MCP server.
    """
    pos = start
    end = min(len(data), start + limit)
    while pos + 32 <= end:
        if data[pos:pos + 2] != START_ID.to_bytes(2, "little"):
            return
        state = data[pos + 2]
        attrs = int.from_bytes(data[pos + 4:pos + 8], "little")
        name_size = int.from_bytes(data[pos + 8:pos + 12], "little")
        data_size = int.from_bytes(data[pos + 12:pos + 16], "little")
        if (name_size == 0 or name_size > MAX_VARIABLE_HEADER
                or (name_size % 2) != 0 or data_size > limit):
            return
        name_off = pos + 32
        data_off = name_off + name_size
        next_pos = (data_off + data_size + 3) & ~3
        if name_off + name_size > end or next_pos > end or next_pos <= pos:
            return
        name = data[name_off:name_off + name_size].decode("utf-16-le", "replace")
        name = name.rstrip("\x00")
        yield {
            "name": name,
            "guid": _guid_at(data, pos + 16),
            "attributes": attrs,
            "attributes_names": attr_names(attrs),
            "name_size": name_size,
            "data_size": data_size,
            "header_offset": pos,
            "data_offset": data_off,
            "data": data[data_off:data_off + data_size],
            "state": state,
            "sensitive": name in SENSITIVE_NAMES or name.startswith(
                ("Boot", "Driver", "Key", "Signature")),
        }
        pos = next_pos


def count_variable_headers(data: bytes, start: int, limit: int) -> tuple[int, int]:
    """Walk variable headers from `start`; return (plausible_count, bytes_consumed)."""
    count = 0
    last_end = start
    for var in iter_variables(data, start, limit):
        count += 1
        last_end = (var["data_offset"] + var["data_size"] + 3) & ~3
        if count >= 512:
            break
    return count, max(0, last_end - start)


def find_marker_offsets(data: bytes) -> list[tuple[int, bytes]]:
    hits: list[tuple[int, bytes]] = []
    for marker in VSS_MARKERS:
        idx = 0
        while True:
            i = data.find(marker, idx)
            if i < 0:
                break
            hits.append((i, marker))
            idx = i + 1
    return sorted(hits)


def probe_store(data: bytes, start: int, size_cap: int) -> tuple[int, int | None]:
    """Try each plausible store-header prefix; return the best (count, var_offset).

    Returns `(0, None)` when no prefix yields a walkable variable-header run.
    """
    best_count, best_at = 0, None
    for prefix in STORE_HEADER_PROBES:
        vstart = start + prefix
        if vstart + 32 > len(data):
            continue
        count, _ = count_variable_headers(data, vstart, min(size_cap, len(data) - vstart))
        if count > best_count:
            best_count, best_at = count, vstart
    return best_count, best_at


def _candidate_from_ffs(data: bytes, ffs: dict, size_cap: int) -> dict | None:
    body_start = ffs["offset"] + ffs["header_size"]
    body_end = min(ffs["offset"] + ffs["size"], len(data))
    count, var_at = probe_store(data, body_start, min(body_end - body_start, size_cap))
    if count < MIN_VARIABLES:
        return None
    return {
        "reason": "ffs-body",
        "offset": body_start,
        "size": min(body_end - body_start, size_cap),
        "confidence": "high" if count >= 3 else "low",
        "variables_validated": count,
        "variable_headers_at": var_at,
        "source_ffs_guid": ffs["guid"],
        "source_ffs_type": ffs["type_name"],
    }


def extract(image_path: str | Path, out_dir: str | Path,
            size_cap: int = DEFAULT_CARVE_SIZE,
            raw_scan: bool = False) -> dict:
    """Locate and carve candidate variable stores; return a manifest."""
    path = Path(image_path)
    data = path.read_bytes()
    out_root = Path(out_dir)
    out_root.mkdir(parents=True, exist_ok=True)

    candidates: list[dict] = []
    notes: list[str] = []

    walk_fv = _load_walk_fv()
    if walk_fv is not None:
        for fv in walk_fv.iter_firmware_volumes(data):
            for ffs in walk_fv.iter_ffs_files(data, fv["offset"], fv["length"],
                                              fv["header_length"]):
                cand = _candidate_from_ffs(data, ffs, size_cap)
                if cand:
                    candidates.append(cand)
    else:
        notes.append("walk_fv module unavailable; FFS-level detection skipped")

    # Marker-based candidates (always on: cheap, and catches stores the FFS walk misses).
    for off, marker in find_marker_offsets(data):
        count, var_at = probe_store(data, off, min(size_cap, len(data) - off))
        if count < MIN_VARIABLES:
            continue
        candidates.append({
            "reason": f"marker:{marker.decode('ascii', 'replace')}",
            "offset": off,
            "size": min(size_cap, len(data) - off),
            "confidence": "high" if count >= 3 else "low",
            "variables_validated": count,
            "variable_headers_at": var_at,
        })

    if raw_scan:
        # Brute force: every aligned 0x55AA run with >= 2 plausible headers.
        pos = 0
        found_offsets = {c["offset"] for c in candidates}
        while pos + 32 <= len(data):
            i = data.find(START_ID.to_bytes(2, "little"), pos)
            if i < 0:
                break
            pos = i + 2
            if i in found_offsets:
                continue
            count, _ = count_variable_headers(data, i, min(size_cap, len(data) - i))
            if count >= 2:
                candidates.append({
                    "reason": "var-headers",
                    "offset": i,
                    "size": min(size_cap, len(data) - i),
                    "confidence": "medium" if count >= 3 else "low",
                    "variables_validated": count,
                })
                found_offsets.add(i)

    # Deduplicate by offset, keeping the highest-confidence/most-specific record.
    rank = {"high": 3, "medium": 2, "low": 1}
    by_offset: dict[int, dict] = {}
    for c in candidates:
        prev = by_offset.get(c["offset"])
        if prev is None or rank.get(c["confidence"], 0) > rank.get(prev["confidence"], 0):
            by_offset[c["offset"]] = c
    ordered = [by_offset[k] for k in sorted(by_offset)]

    carved = []
    for i, c in enumerate(ordered):
        blob = data[c["offset"]:c["offset"] + c["size"]]
        dest = out_root / f"vss_{i:02d}_{c['offset']:#010x}.bin"
        dest.write_bytes(blob)
        entry = dict(c)
        entry["offset"] = hex(c["offset"])
        if entry.get("variable_headers_at") is not None:
            entry["variable_headers_at"] = hex(entry["variable_headers_at"])
        entry["carved_path"] = str(dest)
        entry["carved_size"] = len(blob)
        carved.append(entry)

    if not carved:
        notes.append(
            "no variable store candidate found — the NVRAM region may be "
            "compressed inside an FFS section (decompress with UEFIExtract first), "
            "or reside in a separate region not present in this image; retry with "
            "--raw-scan")

    return {
        "tool": "qi-nx-extract-vss",
        "author": "Qi-NX",
        "image": str(path),
        "size": len(data),
        "out_dir": str(out_root),
        "candidates": carved,
        "notes": notes,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image")
    ap.add_argument("--out", required=True, help="directory for carved stores")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--size", type=int, default=DEFAULT_CARVE_SIZE,
                    help=f"max bytes to carve per candidate (default {DEFAULT_CARVE_SIZE})")
    ap.add_argument("--raw-scan", action="store_true",
                    help="also brute-force scan for 0x55AA variable-header runs")
    args = ap.parse_args()

    path = Path(args.image)
    if not path.is_file():
        print(f"not a file: {path}", file=sys.stderr)
        return 2

    info = extract(path, args.out, args.size, args.raw_scan)

    if args.json:
        print(json.dumps(info, indent=2))
        return 0

    print(f"# extract_vss — {info['image']}")
    print(f"# {BANNER}")
    print(f"size={info['size']} candidates={len(info['candidates'])}")
    for c in info["candidates"]:
        print(f"  {c['offset']:>10} size=0x{c['carved_size']:x} "
              f"vars={c['variables_validated']:3} conf={c['confidence']:6} "
              f"reason={c['reason']} -> {c['carved_path']}")
    for note in info["notes"]:
        print(f"\nnote: {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
