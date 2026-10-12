#!/usr/bin/env python3
"""Qi-NX-Agent: LIEF-based triage for PE / ELF / Mach-O / DEX / OAT / ART / VDEX.

Usage:
    python lief_info.py <binary> [--json] [--sections] [--imports] [--exports] [--relocs]

The public entry point is `info(path, ...)`, which returns a JSON-safe dict and is
also consumed by the Qi-NX MCP server, so the CLI and MCP tool can never report
different results.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

BANNER = "by Qi-NX-Agent (Copyright Qi-NX)"


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _arch_of(bin_obj) -> str:
    """Best-effort architecture label across LIEF versions and formats."""
    header = getattr(bin_obj, "header", None)
    for attr in ("machine_type", "architecture", "machine"):
        try:
            val = getattr(header, attr)
        except Exception:
            continue
        if val is None:
            continue
        text = str(val).split(".")[-1]
        if text and text.lower() not in {"none", "unknown"}:
            return text
    return "?"


def _summarize_section(s) -> dict:
    return {
        "name": getattr(s, "name", "?"),
        "vaddr": hex(getattr(s, "virtual_address", 0)),
        "vsize": hex(getattr(s, "virtual_size", 0)),
        "offset": hex(getattr(s, "offset", 0)),
        "size": hex(getattr(s, "size", 0)),
        "entropy": round(getattr(s, "entropy", 0.0), 3),
    }


def info(target: str | Path, sections: bool = False, imports: bool = False,
         exports: bool = False, relocs: bool = False) -> dict:
    """Return a JSON-safe triage summary, or `{"error": ...}` on failure."""
    path = Path(target)
    if not path.is_file():
        return {"error": f"not a file: {path}"}

    try:
        import lief  # noqa: WPS433 — runtime optional dependency
    except ImportError:
        return {"error": "lief not installed; run `python -m pip install lief`"}

    bin_obj = lief.parse(str(path))
    if bin_obj is None:
        return {"error": f"lief could not parse: {path}"}

    out: dict = {
        "tool": "qi-nx-lief-info",
        "author": "Qi-NX",
        "target": str(path),
        "sha256": sha256_of(path),
        "size": path.stat().st_size,
        "format": str(bin_obj.format).split(".")[-1],
        "arch": _arch_of(bin_obj),
    }
    for key, getter in (
        ("entrypoint", lambda o: hex(o.entrypoint)),
        ("imagebase", lambda o: hex(o.imagebase)),
        ("is_pie", lambda o: bool(o.is_pie)),
        ("has_nx", lambda o: bool(o.has_nx)),
        ("has_canary", lambda o: bool(getattr(o, "has_canary", False))),
    ):
        try:
            out[key] = getter(bin_obj)
        except Exception:
            pass

    if sections:
        try:
            out["sections"] = [_summarize_section(s) for s in bin_obj.sections]
        except Exception as e:
            out["sections_error"] = str(e)
    if imports:
        try:
            imported = (getattr(bin_obj, "imports", None)
                        or getattr(bin_obj, "imported_libraries", []))
            entries = []
            for lib in imported:
                name = getattr(lib, "name", "?")
                syms = [getattr(e, "name", "?") for e in (getattr(lib, "entries", None) or [])]
                entries.append({"name": name, "symbols": syms[:64]} if syms
                               else {"name": name})
            out["imports"] = entries[:64]
        except Exception as e:
            out["imports_error"] = str(e)
    if exports:
        try:
            exported = getattr(bin_obj, "exported_functions", [])
            out["exports"] = [getattr(e, "name", str(e)) for e in exported][:128]
        except Exception as e:
            out["exports_error"] = str(e)
    if relocs:
        try:
            out["relocations_count"] = len(list(bin_obj.relocations))
        except Exception as e:
            out["relocations_error"] = str(e)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target", help="binary to inspect")
    ap.add_argument("--json", action="store_true", help="emit JSON only")
    ap.add_argument("--sections", action="store_true")
    ap.add_argument("--imports", action="store_true")
    ap.add_argument("--exports", action="store_true")
    ap.add_argument("--relocs", action="store_true")
    args = ap.parse_args()

    out = info(args.target, args.sections, args.imports, args.exports, args.relocs)
    if "error" in out:
        print(out["error"], file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(out, indent=2))
        return 0

    print(f"# lief_info — {out['target']}")
    print(f"# {BANNER}")
    for k, v in out.items():
        if k in {"sections", "imports", "exports", "tool", "author", "target"}:
            continue
        print(f"{k}: {v}")
    if args.sections and "sections" in out:
        print("\n## sections")
        for s in out["sections"]:
            print(f"  {s['name']:10} vaddr={s['vaddr']} vsize={s['vsize']} "
                  f"entropy={s['entropy']}")
    if args.imports and "imports" in out:
        print("\n## imports")
        for i in out["imports"]:
            syms = i.get("symbols") or []
            print(f"  {i['name']}{f' ({len(syms)} syms)' if syms else ''}")
    if args.exports and "exports" in out:
        print("\n## exports")
        for name in out["exports"]:
            print(f"  {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
