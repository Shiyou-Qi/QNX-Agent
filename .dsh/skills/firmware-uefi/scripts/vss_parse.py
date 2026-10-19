#!/usr/bin/env python3
"""QNX-Agent (Firmware / UEFI): decode UEFI NVRAM variables from an image or a
carved variable-store blob.

Usage:
    python vss_parse.py <image-or-carved-store> [--json] [--variable NAME] [--list]

Pairs with `extract_vss.py`: carve the store first, then decode it here. Both
share one implementation of the EDK2 variable-header layout
(`extract_vss.iter_variables`), so they can never disagree about a store.

Locating a store:
  1. `_VSS` / `_VSS2` ASCII markers, with the store header (28–32 bytes) probed
     so the first variable header is found rather than assumed.
  2. A fallback scan for a run of plausible `0x55AA` variable headers, which
     covers stores whose signature was stripped.

Sensitive names (BootOrder, SecureBoot, PK/KEK/db/dbx, Setup families, Key####)
are flagged so a trust-state review can start from the report.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

BANNER = "by QNX-Agent (Copyright Qi-NX)"

try:
    import extract_vss  # type: ignore  # sibling module
except Exception:  # pragma: no cover - defensive
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import extract_vss  # type: ignore

MIN_VARIABLES = extract_vss.MIN_VARIABLES


def find_store_candidates(data: bytes, size_cap: int = 0x40000) -> list[dict]:
    """Return candidate stores as {store_offset, variables_at, variables_probed}."""
    candidates: list[dict] = []
    seen: set[int] = set()

    for off, marker in extract_vss.find_marker_offsets(data):
        count, var_at = extract_vss.probe_store(data, off, min(size_cap, len(data) - off))
        if count >= MIN_VARIABLES and var_at is not None:
            candidates.append({
                "store_offset": off,
                "variables_at": var_at,
                "variables_probed": count,
                "detected_by": f"marker:{marker.decode('ascii', 'replace')}",
            })
            seen.add(off)

    # Fallback: a bare 0x55AA run (the store signature may be absent).
    if not candidates:
        pos = 0
        start_id = extract_vss.START_ID.to_bytes(2, "little")
        while pos + 32 <= len(data):
            i = data.find(start_id, pos)
            if i < 0:
                break
            pos = i + 2
            if i in seen:
                continue
            count, _ = extract_vss.count_variable_headers(
                data, i, min(size_cap, len(data) - i))
            if count >= MIN_VARIABLES:
                candidates.append({
                    "store_offset": i,
                    "variables_at": i,
                    "variables_probed": count,
                    "detected_by": "var-headers",
                })
                seen.add(i)
                break
    return candidates


def parse(image_path: str | Path, variable: str | None = None,
          size_cap: int = 0x40000) -> dict:
    """Decode every variable found in the image (optionally filtered by name)."""
    path = Path(image_path)
    data = path.read_bytes()

    result: dict = {
        "tool": "qi-nx-vss-parse",
        "author": "Qi-NX",
        "image": str(path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "stores": [],
        "variables": [],
        "notes": [],
    }

    candidates = find_store_candidates(data, size_cap)
    if not candidates:
        result["notes"].append(
            "no variable store found — the NVRAM region may be compressed inside "
            "an FFS section (decompress with UEFIExtract), or reside outside this "
            "image; run extract_vss.py --raw-scan to carve candidates first")

    for cand in candidates:
        limit = min(size_cap, len(data) - cand["variables_at"])
        parsed = list(extract_vss.iter_variables(data, cand["variables_at"], limit))
        # UEFI variable stores can retain deleted copies. Prefer a fully-added
        # copy; a transition copy is current only if no added copy of the same
        # (name, vendor GUID) exists in this store.
        selected_indices = set()
        selected_keys = set()
        for state in (0x3F, 0x3E):
            for index in range(len(parsed) - 1, -1, -1):
                var = parsed[index]
                key = (var["guid"], var["name"])
                if var["state"] == state and key not in selected_keys:
                    selected_indices.add(index)
                    selected_keys.add(key)

        variables = []
        for index, var in enumerate(parsed):
            if variable and var["name"] != variable:
                continue
            variables.append({
                "name": var["name"],
                "guid": var["guid"],
                "attributes": hex(var["attributes"]),
                "attributes_names": var["attributes_names"],
                "state": hex(var["state"]),
                "state_name": var["state_name"],
                "current": index in selected_indices,
                "size": var["data_size"],
                "header_offset": hex(var["header_offset"]),
                "data_offset": hex(var["data_offset"]),
                "data_preview_hex": var["data"][:32].hex(),
                "sensitive": var["sensitive"],
            })
        result["stores"].append({
            "store_offset": hex(cand["store_offset"]),
            "variables_at": hex(cand["variables_at"]),
            "detected_by": cand["detected_by"],
            "variables_probed": cand["variables_probed"],
            "variables_emitted": len(variables),
        })
        result["variables"].extend(variables)

    if any(not var["current"] for var in result["variables"]):
        result["notes"].append(
            "historical or incomplete variable records are included; use current=true "
            "for the selected live copy and retain other states as forensic evidence")

    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image", help="firmware image or a store carved by extract_vss.py")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--variable", help="only report this exact variable name")
    ap.add_argument("--list", action="store_true", help="omit data previews")
    ap.add_argument("--size-cap", type=int, default=0x40000)
    args = ap.parse_args()

    path = Path(args.image)
    if not path.is_file():
        print(f"not a file: {path}", file=sys.stderr)
        return 2

    info = parse(path, args.variable, args.size_cap)

    if args.json:
        print(json.dumps(info, indent=2))
        return 0

    print(f"# vss_parse — {info['image']}")
    print(f"# {BANNER}")
    print(f"size={info['size']} stores={len(info['stores'])} "
          f"variables={len(info['variables'])}")
    for store in info["stores"]:
        print(f"\nstore @ {store['store_offset']} vars@{store['variables_at']} "
              f"detected_by={store['detected_by']} "
              f"emitted={store['variables_emitted']}")
    if info["variables"]:
        print("\nvariables:")
    for v in info["variables"]:
        sens = " [SENSITIVE]" if v["sensitive"] else ""
        current = " [CURRENT]" if v["current"] else " [HISTORICAL/INCOMPLETE]"
        attrs = "+".join(v["attributes_names"]) or "none"
        print(f"  {v['name']:<32} {v['guid']} attrs={v['attributes']:<10} "
              f"({attrs}) state={v['state_name']} size=0x{v['size']:x}"
              f"{current}{sens}")
        if not args.list:
            print(f"      data[:32]={v['data_preview_hex']}")
    for note in info["notes"]:
        print(f"\nnote: {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
