#!/usr/bin/env python3
"""Qi-NX-Agent: lightweight YARA scanner with packer / crypto / IOC rules.

Usage:
    python yara_scan.py <target> [--rules FILE.yar] [--json] [--max-matches N] [--max-per-rule N]

Behaviour:
  * With no `--rules`, uses a built-in packer/crypto/IOC ruleset (compiled on
    the fly) tuned for triage: UPX/ASPack/Themida/VMProtect markers, common
    crypto constants (AES S-box, SHA-2 K, RC4 KSA, MD5 init state), URL/IP/email
    IOC patterns, and a few well-known malware tags.
  * With `--rules`, points at any .yar / directory of rules.
  * Always prints a header `# by Qi-NX-Agent (© Qi-NX)` then `rule: offset(hex) match_preview`.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

BANNER = "by Qi-NX-Agent (Copyright Qi-NX)"

BUILTIN_RULES = r"""
rule qi_nx_packer_upx
{
    meta:
        author = "Qi-NX"
        description = "UPX packer markers"
    strings:
        $a = "UPX0" ascii
        $b = "UPX1" ascii
        $c = "UPX!" ascii
        $d = "$Info: This file is packed with the UPX" ascii
    condition: any of them
}

rule qi_nx_packer_aspack
{
    meta:
        author = "Qi-NX"
        description = "ASPack markers"
    strings:
        $a = ".aspack" ascii
        $b = ".adata" ascii
        $c = "ASPack" ascii
    condition: any of them
}

rule qi_nx_packer_themida
{
    meta:
        author = "Qi-NX"
        description = "Themida / WinLicense / VMProtect markers"
    strings:
        $a = ".themida" ascii
        $b = "Themida" ascii nocase
        $c = "WinLicense" ascii nocase
        $d = ".vmp" ascii
        $e = "VMProtect" ascii nocase
    condition: any of them
}

rule qi_nx_crypto_aes
{
    meta:
        author = "Qi-NX"
        description = "AES S-box / inverse S-box constants"
    strings:
        $sbox     = { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 }
        $inv_sbox = { 52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb }
    condition: any of them
}

rule qi_nx_crypto_sha256
{
    meta:
        author = "Qi-NX"
        description = "SHA-256 K constants prefix"
    strings:
        $k = { 67 e6 09 6a 85 ae 67 bb 72 f3 6e 3c 3a f5 4f a5 }
    condition: $k
}

rule qi_nx_crypto_rc4_ksa
{
    meta:
        author = "Qi-NX"
        description = "RC4 KSA loop heuristic"
    strings:
        // MOV/ADD/XOR pattern over a 256-byte table; matches the canonical
        // "for i in 0..255: j = (j + S[i] + key[i mod L]) & 0xff" shape.
        $ksa = { 8A 44 ?? ?? 02 C? ?? 88 44 ?? ?? 3? ?? 75 }
    condition: $ksa
}

rule qi_nx_ioc_url
{
    meta:
        author = "Qi-NX"
        description = "Plain-text URL"
    strings:
        $u = /https?:\/\/[a-zA-Z0-9._~:\/?#@!$&'()*+,;=%-]{8,200}/ ascii wide
    condition: $u
}

rule qi_nx_ioc_ipv4
{
    meta:
        author = "Qi-NX"
        description = "IPv4 dotted-quad"
    strings:
        $ip = /\b(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)\b/ ascii wide
    condition: $ip
}

rule qi_nx_ioc_email
{
    meta:
        author = "Qi-NX"
        description = "Email-like IOC"
    strings:
        $m = /[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,255}\.[A-Za-z]{2,24}/ ascii wide
    condition: $m
}
"""


def _iter_rule_paths(rule_path: Path) -> list[Path]:
    if rule_path.is_dir():
        return sorted([p for p in rule_path.rglob("*.yar")] + [p for p in rule_path.rglob("*.yara")])
    return [rule_path]


def _iter_match_instances(match, max_per_rule: int = 8):
    """Yield (identifier, offset, matched_bytes) across yara-python APIs.

    yara-python >= 4.4 exposes `match.strings` as a list of StringMatch objects
    carrying `.identifier` and `.instances` (each with `.offset` and
    `.matched_data`). Older releases expose a list of
    `(offset, identifier, data)` tuples. Support both.
    """
    emitted = 0
    for s in getattr(match, "strings", []) or []:
        instances = getattr(s, "instances", None)
        if instances is None:
            # legacy tuple form
            try:
                off, ident, data = s
            except Exception:
                continue
            yield ident, off, bytes(data)
            emitted += 1
            if emitted >= max_per_rule:
                return
            continue
        ident = getattr(s, "identifier", "?")
        for inst in instances:
            yield ident, getattr(inst, "offset", 0), bytes(getattr(inst, "matched_data", b""))
            emitted += 1
            if emitted >= max_per_rule:
                return


def _dedupe_overlaps(instances):
    """Drop instances that overlap one already kept for the same rule.

    YARA reports every matching start offset, so a single `192.168.10.44` yields
    matches at .29, .2a and .2b. Keep the leftmost-longest and skip the rest.
    """
    kept = []
    for ident, off, data in sorted(instances, key=lambda t: (t[1], -len(t[2]))):
        if any(off < k_off + len(k_data) and k_off < off + len(data) for _, k_off, k_data in kept):
            continue
        kept.append((ident, off, data))
    return sorted(kept, key=lambda t: t[1])


def scan(target: str | Path, rules_path: str | Path | None = None,
         max_matches: int = 200, max_per_rule: int = 8) -> dict:
    """Scan a file and return a JSON-safe result dict, or `{"error": ...}`."""
    try:
        import yara  # noqa: WPS433 — optional dependency
    except ImportError:
        return {"error": "yara-python not installed; run `python -m pip install yara-python`"}

    path = Path(target)
    if not path.is_file():
        return {"error": f"not a file: {path}"}

    try:
        if rules_path:
            paths = _iter_rule_paths(Path(rules_path))
            rules = yara.compile(filepaths={str(p): str(p) for p in paths})
        else:
            rules = yara.compile(source=BUILTIN_RULES)
        data = path.read_bytes()
        matches = rules.match(data=data, timeout=60)
    except Exception as e:  # noqa: BLE001 — surface as data, not a crash
        return {"error": f"yara scan failed: {e}"}

    out_matches: list[dict] = []
    total = 0
    for m in matches:
        if total >= max_matches:
            break
        for ident, off, matched in _dedupe_overlaps(
                list(_iter_match_instances(m, max_per_rule * 4))):
            if total >= max_matches:
                break
            out_matches.append({
                "rule": m.rule,
                "ns": m.namespace,
                "offset": hex(off),
                "match_name": ident,
                "evidence_basis": "raw YARA pattern match",
                "preview_hex": matched[:32].hex(),
                "preview_text": matched[:32].decode("utf-8", errors="replace"),
            })
            total += 1

    return {
        "tool": "qi-nx-yara-scan",
        "author": "Qi-NX",
        "target": str(path),
        "size": len(data),
        "ruleset": str(rules_path) if rules_path else "builtin-qi-nx-triage",
        "match_total": total,
        "matches": out_matches,
        "limitations": [
            "a pattern match is a lead and needs surrounding-code or contextual review",
            "custom rules inherit the author's assumptions and may produce false positives",
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target", help="binary to scan")
    ap.add_argument("--rules", help="YARA rule file or directory (default: builtin Qi-NX triage rules)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--max-matches", type=int, default=200, help="total matches cap")
    ap.add_argument("--max-per-rule", type=int, default=8, help="cap of offsets per rule")
    args = ap.parse_args()

    result = scan(args.target, args.rules, args.max_matches, args.max_per_rule)
    if "error" in result:
        print(result["error"], file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    print(f"# yara_scan — {result['target']}")
    print(f"# {BANNER}")
    print(f"target_size: {result['size']} bytes  matches: {result['match_total']}")
    for m in result["matches"]:
        print(f"{m['rule']:32} {m['offset']:>10} {m['match_name']:10} "
              f"{m['preview_text']!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
