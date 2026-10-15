#!/usr/bin/env python3
"""Compare UEFI firmware images or extracted payload directories.

Image comparisons match FV instances by filesystem GUID and FFS instances by
file GUID/type, then compare complete-file and section-payload hashes. Directory
comparisons match relative paths and compare SHA-256. This tool is read-only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

import walk_fv

BANNER = "by Qi-NX-Agent (Copyright Qi-NX)"
MAX_IMAGE_SIZE = 512 * 1024 * 1024
MAX_TREE_FILES = 10000
MAX_DIFF_DETAILS = 500


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _inventory_image(path: Path) -> dict:
    size = path.stat().st_size
    if size > MAX_IMAGE_SIZE:
        raise ValueError(f"image exceeds {MAX_IMAGE_SIZE} byte safety cap: {path}")
    data = path.read_bytes()
    walked = walk_fv.walk(path)
    fv_ordinals = defaultdict(int)
    firmware_volumes = []
    all_files = {}
    for fv in walked["firmware_volumes"]:
        guid = fv["file_system_guid"]
        fv_index = fv_ordinals[guid]
        fv_ordinals[guid] += 1
        fv_key = f"{guid}#{fv_index}"
        file_ordinals = defaultdict(int)
        files = []
        for ffs in fv["files"]:
            ffs_guid = ffs["guid"]
            file_type = ffs["type_name"]
            duplicate_index = file_ordinals[(ffs_guid, file_type)]
            file_ordinals[(ffs_guid, file_type)] += 1
            key = f"{fv_key}/{ffs_guid}/{file_type}#{duplicate_index}"
            offset = int(ffs["offset"], 16)
            raw = data[offset:offset + int(ffs["size"])]
            section_digest = hashlib.sha256()
            for section in ffs["sections"]:
                payload_offset = int(section["payload_offset"], 16)
                payload_size = int(section["payload_size"])
                section_digest.update(bytes([section["type"]]))
                section_digest.update(payload_size.to_bytes(8, "little"))
                section_digest.update(data[payload_offset:payload_offset + payload_size])
            record = {
                "key": key,
                "fv_guid": guid,
                "ffs_guid": ffs_guid,
                "type": file_type,
                "offset": ffs["offset"],
                "size": int(ffs["size"]),
                "sha256": _hash(raw),
                "section_payload_sha256": section_digest.hexdigest(),
                "section_types": [section["type_name"] for section in ffs["sections"]],
                "needs_decompression": any(section.get("needs_decompression")
                                            for section in ffs["sections"]),
            }
            files.append(record)
            all_files[key] = record
        firmware_volumes.append({
            "key": fv_key,
            "guid": guid,
            "offset": fv["offset"],
            "length": int(fv["length"]),
            "file_total": len(files),
            "files": files,
        })
    return {
        "kind": "firmware-image",
        "path": str(path),
        "size": size,
        "sha256": _hash(data),
        "firmware_volume_total": len(firmware_volumes),
        "file_total": len(all_files),
        "firmware_volumes": firmware_volumes,
        "files": all_files,
        "notes": walked["notes"],
    }


def _inventory_directory(path: Path) -> dict:
    files = {}
    all_items = sorted(path.rglob("*"))
    truncated = False
    for item in all_items:
        if not item.is_file():
            continue
        resolved = item.resolve()
        if not resolved.is_relative_to(path.resolve()):
            continue
        size = item.stat().st_size
        if size > MAX_IMAGE_SIZE:
            continue
        digest = hashlib.sha256()
        with item.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        key = str(item.relative_to(path)).replace("\\", "/")
        files[key] = {"path": key, "size": size, "sha256": digest.hexdigest()}
        if len(files) >= MAX_TREE_FILES:
            truncated = len(all_items) > len(files)
            break
    return {"kind": "extracted-directory", "path": str(path),
            "file_total": len(files), "truncated": truncated, "files": files}


def _compare_files(before: dict, after: dict, semantic: bool) -> dict:
    old, new = before["files"], after["files"]
    added, removed, modified, unchanged = [], [], [], []
    added_total = removed_total = modified_total = unchanged_total = 0
    for key in sorted(set(old) | set(new)):
        if key not in old:
            added_total += 1
            if len(added) < MAX_DIFF_DETAILS:
                added.append(new[key])
        elif key not in new:
            removed_total += 1
            if len(removed) < MAX_DIFF_DETAILS:
                removed.append(old[key])
        elif old[key]["sha256"] == new[key]["sha256"]:
            unchanged_total += 1
        else:
            row = {"key": key, "before": old[key], "after": new[key]}
            if semantic:
                row["payload_changed"] = (
                    old[key]["section_payload_sha256"] !=
                    new[key]["section_payload_sha256"])
            modified_total += 1
            if len(modified) < MAX_DIFF_DETAILS:
                modified.append(row)
    return {"added": added, "removed": removed, "modified": modified,
            "unchanged_total": unchanged_total, "added_total": added_total,
            "removed_total": removed_total, "modified_total": modified_total,
            "detail_limit_per_category": MAX_DIFF_DETAILS,
            "details_truncated": (added_total > len(added)
                                  or removed_total > len(removed)
                                  or modified_total > len(modified))}


def compare(baseline: str | Path, candidate: str | Path,
            baseline_extracted: str | Path | None = None,
            candidate_extracted: str | Path | None = None) -> dict:
    """Compare two images, two directories, and optionally extracted payloads."""
    before_path = Path(baseline).expanduser().resolve()
    after_path = Path(candidate).expanduser().resolve()
    if not before_path.exists() or not after_path.exists():
        return {"error": "both baseline and candidate paths must exist"}
    if before_path.is_dir() != after_path.is_dir():
        return {"error": "baseline and candidate must both be images or both be directories"}
    try:
        if before_path.is_dir():
            before = _inventory_directory(before_path)
            after = _inventory_directory(after_path)
            image_comparison = None
            extracted_comparison = _compare_files(before, after, False)
        else:
            before = _inventory_image(before_path)
            after = _inventory_image(after_path)
            image_comparison = _compare_files(before, after, True)
            extracted_comparison = None
        if bool(baseline_extracted) != bool(candidate_extracted):
            return {"error": "provide both extracted directories or neither"}
        if baseline_extracted:
            old_dir = Path(baseline_extracted).expanduser().resolve()
            new_dir = Path(candidate_extracted).expanduser().resolve()
            if not old_dir.is_dir() or not new_dir.is_dir():
                return {"error": "extracted paths must both be existing directories"}
            extracted_comparison = _compare_files(_inventory_directory(old_dir),
                                                   _inventory_directory(new_dir), False)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"firmware comparison failed: {exc}"}
    return {
        "tool": "qi-nx-firmware-diff",
        "author": "Qi-NX",
        "baseline": {k: v for k, v in before.items()
                     if k not in {"files", "firmware_volumes"}},
        "candidate": {k: v for k, v in after.items()
                      if k not in {"files", "firmware_volumes"}},
        "baseline_firmware_volumes": [
            {k: fv[k] for k in ("key", "guid", "offset", "length", "file_total")}
            for fv in before.get("firmware_volumes", [])],
        "candidate_firmware_volumes": [
            {k: fv[k] for k in ("key", "guid", "offset", "length", "file_total")}
            for fv in after.get("firmware_volumes", [])],
        "image_comparison": image_comparison,
        "extracted_payload_comparison": extracted_comparison,
        "limitations": [
            "FFS matching uses FV filesystem GUID, FFS file GUID/type, and duplicate occurrence order",
            "whole-file hashes include FFS header/state/checksum changes; section-payload hashes help separate payload changes",
            "compressed/GUID-defined contents remain opaque unless extracted with UEFIExtract or another decompressor first",
            "a structural or hash difference is not by itself a vulnerability finding",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline")
    parser.add_argument("candidate")
    parser.add_argument("--baseline-extracted")
    parser.add_argument("--candidate-extracted")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = compare(args.baseline, args.candidate, args.baseline_extracted,
                     args.candidate_extracted)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif "error" in result:
        print(result["error"], file=sys.stderr)
        return 2
    else:
        print(f"# firmware_diff — {args.baseline} → {args.candidate}\n# {BANNER}")
        comparison = result["image_comparison"] or result["extracted_payload_comparison"]
        for key in ("added", "removed", "modified", "unchanged"):
            print(f"{key}: {comparison.get(key + '_total', 0)}")
        for row in comparison["modified"][:50]:
            print(f"modified: {row['key']}")
    return 0 if "error" not in result else 2


if __name__ == "__main__":
    sys.exit(main())
