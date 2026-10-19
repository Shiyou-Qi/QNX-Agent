#!/usr/bin/env python3
"""QNX-Agent: packer / protection detection.

Usage:
    python pack_detect.py <binary> [--json]

The public entry point is `detect(path)`, which returns a JSON-safe dict and is
also consumed by the Qi-NX MCP server.

Behaviour:
  * Computes per-section entropy and overall entropy.
  * Runs a curated packer / virtualizer / protector signature scan based on
    section-name patterns and import-table shape.
  * Emits a `verdict` with an explicit `confidence` note.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

BANNER = "by QNX-Agent (Copyright Qi-NX)"

ENTROPY_HIGH = 7.0
ENTROPY_VERY_HIGH = 7.5

PACKER_SECTION_HINTS = [
    ("UPX", re.compile(r"^UPX[012!]?$", re.I)),
    ("ASPack", re.compile(r"^\.aspack$|^\.adata$", re.I)),
    ("PECompact", re.compile(r"PEC(2|$)", re.I)),
    ("Themida/WinLicense", re.compile(r"^\.themida$|^\.winlice", re.I)),
    ("VMProtect", re.compile(r"^\.vmp[012]$|^\.vmp$", re.I)),
    ("MoleBox", re.compile(r"^\.molebox$", re.I)),
    ("MPRESS", re.compile(r"^\.MPRESS[12]$", re.I)),
    ("Petite", re.compile(r"^\.petite", re.I)),
    ("FSG", re.compile(r"^\.fsg$", re.I)),
    ("NsPack", re.compile(r"^\.\?nsp[0-9]$", re.I)),
    ("Enigma", re.compile(r"^\.enigma[12]$", re.I)),
    ("Obsidium", re.compile(r"^\.obsidium$", re.I)),
]

PROTECTOR_IMPORT_HINTS = {
    "VMProtect": re.compile(r"VMProtect(Begin|End|IsProtected|IsDebuggerPresent)", re.I),
    "Themida": re.compile(r"Themida|WinLicense", re.I),
    "Obsidium": re.compile(r"Obsidium", re.I),
    "Enigma": re.compile(r"Enigma", re.I),
}


def _entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    counts = Counter(buf)
    total = len(buf)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def detect(target: str | Path) -> dict:
    """Return packer/protector analysis as a JSON-safe dict, or `{"error": ...}`."""
    path = Path(target)
    if not path.is_file():
        return {"error": f"not a file: {path}"}

    try:
        import lief  # noqa: WPS433 — optional dependency
    except ImportError:
        return {"error": "lief not installed; run `python -m pip install lief`"}

    data = path.read_bytes()
    bin_obj = lief.parse(str(path))
    if bin_obj is None:
        return {"error": f"lief could not parse: {path}"}

    sections: list[dict] = []
    sections_error = None
    try:
        for s in bin_obj.sections:
            sections.append({
                "name": s.name,
                "vsize": getattr(s, "virtual_size", 0),
                "size": getattr(s, "size", 0),
                "entropy": round(getattr(s, "entropy", 0.0), 3),
            })
    except Exception as e:  # noqa: BLE001
        sections_error = str(e)

    imported_names: list[str] = []
    try:
        for lib in bin_obj.imports or []:
            for entry in getattr(lib, "entries", []) or []:
                name = getattr(entry, "name", None)
                if name:
                    imported_names.append(name)
    except Exception:
        pass

    packer_hits: list[str] = []
    evidence: list[dict] = []
    for s in sections:
        for name, rx in PACKER_SECTION_HINTS:
            if rx.match(s["name"]):
                hit = f"{name} (section {s['name']})"
                packer_hits.append(hit)
                evidence.append({"kind": "section-name", "signal": hit,
                                 "section": s["name"]})

    import_hits: list[str] = []
    for name, rx in PROTECTOR_IMPORT_HINTS.items():
        if any(rx.search(n) for n in imported_names):
            import_hits.append(name)
            matched_imports = [n for n in imported_names if rx.search(n)]
            evidence.append({"kind": "import-name", "signal": name,
                             "matches": matched_imports[:16]})

    high_entropy_count = sum(1 for s in sections if s["entropy"] >= ENTROPY_HIGH)
    very_high_entropy_count = sum(
        1 for s in sections if s["entropy"] >= ENTROPY_VERY_HIGH)
    for s in sections:
        if s["entropy"] >= ENTROPY_HIGH:
            evidence.append({"kind": "high-entropy-section", "section": s["name"],
                             "entropy": s["entropy"], "threshold": ENTROPY_HIGH})

    # Verdict heuristics, each with the reasoning recorded in `confidence`.
    if packer_hits or import_hits:
        verdict = "packed-known"
        confidence = "medium (heuristic section-name and/or import markers; independently corroborate)"
    elif very_high_entropy_count >= max(1, len(sections) // 2):
        verdict = "packed-unknown"
        confidence = "medium (most sections entropy >= 7.5)"
    elif high_entropy_count >= 1 and len(imported_names) < 10:
        verdict = "packed-unknown"
        confidence = "low (one high-entropy section + tiny import table)"
    else:
        verdict = "no-known-packer-indicators"
        confidence = "low (absence of these indicators does not establish that the file is unpacked)"

    out = {
        "tool": "qi-nx-pack-detect",
        "author": "Qi-NX",
        "target": str(path),
        "size": len(data),
        "entropy_overall": round(_entropy(data), 3),
        "sections": sections,
        "imports_sample": imported_names[:32],
        "imports_count": len(imported_names),
        "packer_hits": packer_hits,
        "protector_import_hits": import_hits,
        "evidence": evidence,
        "verdict": verdict,
        "confidence": confidence,
        "limitations": [
            "heuristic triage only; section names and imports can be forged or removed",
            "high entropy can result from legitimate compressed or encrypted resources",
            "no-known-packer-indicators is not a clean-file verdict",
        ],
    }
    if sections_error:
        out["sections_error"] = sections_error
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target", help="binary to inspect")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    out = detect(args.target)
    if "error" in out:
        print(out["error"], file=sys.stderr)
        return 3 if "could not parse" in out["error"] else 2

    if args.json:
        print(json.dumps(out, indent=2))
        return 0

    print(f"# pack_detect — {out['target']}")
    print(f"# {BANNER}")
    print(f"size={out['size']} entropy_overall={out['entropy_overall']} "
          f"imports_count={out['imports_count']}")
    if out["sections"]:
        print("\nsections:")
        for s in out["sections"]:
            print(f"  {s['name'] or '?':12} vsize=0x{s['vsize']:x} "
                  f"size=0x{s['size']:x} entropy={s['entropy']}")
    hits = out["packer_hits"] + out["protector_import_hits"]
    if hits:
        print("\nhits:")
        for h in hits:
            print(f"  - {h}")
    print(f"\nverdict: {out['verdict']}")
    print(f"confidence: {out['confidence']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
