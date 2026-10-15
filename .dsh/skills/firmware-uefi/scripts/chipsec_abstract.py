#!/usr/bin/env python3
"""Qi-NX-Agent (Firmware / UEFI): chipsec findings summariser.

Usage:
    python chipsec_abstract.py <chipsec-log.txt> [--json]

Behaviour:
  * Parse a chipsec_main / chipsec_util log file.
  * Group by module, extract result line (`[!]`, `[+]`, `[*]`, `[-]`) and turn
    them into structured JSON the agent can synthesise into an audit narrative.
  * Always prints the banner `# by Qi-NX-Agent (© Qi-NX)`.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

BANNER = "by Qi-NX-Agent (Copyright Qi-NX)"

MODULE_RX = re.compile(r"^\[\*\]\s+running module:\s+(\S+)")
RESULT_RX = re.compile(r"^\[([!\+\-\*x])\]\s+(.*)$")
SUMMARY_RX = re.compile(r"^\[CHIPSEC\]\s+(.*)$")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("log", help="chipsec log file")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    path = Path(args.log)
    if not path.is_file():
        print(f"not a file: {path}", file=sys.stderr)
        return 2

    modules = []
    current = None
    for raw in path.read_text(errors="replace").splitlines():
        line = raw.rstrip()
        m = MODULE_RX.match(line)
        if m:
            current = {"module": m.group(1), "results": []}
            modules.append(current)
            continue
        r = RESULT_RX.match(line)
        if r and current is not None:
            sym, text = r.groups()
            status = {"!": "FAIL", "+": "PASS", "-": "ERROR", "*": "INFO", "x": "SKIPPED"}[sym]
            current["results"].append({"status": status, "message": text})
            continue
        s = SUMMARY_RX.match(line)
        if s:
            summary = next((m for m in modules if m["module"] == "__SUMMARY__"), None)
            if summary is None:
                summary = {"module": "__SUMMARY__", "results": []}
                modules.append(summary)
            summary["results"].append({"status": "INFO", "message": s.group(1)})

    if args.json:
        print(json.dumps({
            "tool": "qi-nx-chipsec-abstract",
            "author": "Qi-NX",
            "log": str(path),
            "modules": modules,
        }, indent=2))
        return 0

    print(f"# chipsec_abstract — {path}")
    print(f"# {BANNER}")
    for m in modules:
        print(f"\n## {m['module']}")
        for r in m["results"][:16]:
            print(f"  [{r['status']:7}] {r['message']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
