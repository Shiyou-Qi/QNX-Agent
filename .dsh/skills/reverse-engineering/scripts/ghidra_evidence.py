#!/usr/bin/env python3
"""Export address-linked static-analysis evidence from Ghidra headless.

Ghidra performs static analysis only; this helper never executes the target.
Usage: python ghidra_evidence.py <binary> [--ghidra PATH] [--json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

BANNER = "by QNX-Agent (Copyright Qi-NX)"
GHIDRA_SCRIPT = Path(__file__).with_name("ghidra_scripts")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _find_ghidra(configured: str | None) -> str | None:
    candidate = configured or os.environ.get("GHIDRA_ANALYZE_HEADLESS")
    if candidate:
        path = Path(candidate)
        if path.is_file():
            return str(path)
        found = shutil.which(candidate)
        if found:
            return found
        return None
    for name in ("analyzeHeadless", "analyzeHeadless.bat", "analyzeHeadless.exe"):
        found = shutil.which(name)
        if found:
            return found
    home = os.environ.get("GHIDRA_HOME")
    if home:
        names = ("analyzeHeadless.bat", "analyzeHeadless.exe") if os.name == "nt" else ("analyzeHeadless",)
        for name in names:
            path = Path(home) / "support" / name
            if path.is_file():
                return str(path)
    return None


def analyze(target: str | Path, ghidra: str | None = None,
            max_functions: int = 5000, timeout: int = 900) -> dict:
    """Run Ghidra headless and return function/callsite evidence as JSON."""
    path = Path(target).expanduser().resolve()
    if not path.is_file():
        return {"error": f"not a file: {path}"}
    if max_functions < 1 or max_functions > 20000:
        return {"error": "max_functions must be between 1 and 20000"}
    if timeout < 30 or timeout > 7200:
        return {"error": "timeout must be between 30 and 7200 seconds"}
    executable = _find_ghidra(ghidra)
    if not executable:
        return {
            "error": "Ghidra analyzeHeadless was not found",
            "hint": "Set GHIDRA_ANALYZE_HEADLESS to its executable path or add Ghidra's support directory to PATH.",
            "environment_variable": "GHIDRA_HOME",
        }
    script = GHIDRA_SCRIPT / "QiNxEvidence.py"
    if not script.is_file():
        return {"error": f"Ghidra evidence script is missing: {script}"}

    with tempfile.TemporaryDirectory(prefix="qinx-ghidra-") as temp:
        root = Path(temp)
        project_dir = root / "project"
        output = root / "evidence.json"
        snapshot = root / "input.bin"
        shutil.copyfile(path, snapshot)
        snapshot_sha256 = _sha256(snapshot)
        project_dir.mkdir()
        if os.name == "nt" and executable.lower().endswith((".bat", ".cmd")):
            shell_meta = set("&|<>^%!\r\n")
            checked_paths = (executable, str(snapshot), str(project_dir),
                             str(GHIDRA_SCRIPT))
            if any(any(char in shell_meta for char in value) for value in checked_paths):
                return {
                    "error": "Windows batch launcher paths contain cmd.exe metacharacters",
                    "hint": "use paths without &, |, <, >, ^, %, or !, or use a native analyzeHeadless executable",
                    "target_sha256": snapshot_sha256,
                }
        cmd = [
            executable, str(project_dir), "qinx-analysis",
            "-import", str(snapshot),
            "-scriptPath", str(GHIDRA_SCRIPT),
            "-postScript", script.name, str(output), str(max_functions),
            "-deleteProject",
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return {"error": "Ghidra analysis timed out", "timeout_seconds": timeout,
                    "target": str(path), "target_sha256": snapshot_sha256,
                    "target_size": snapshot.stat().st_size}
        except OSError as exc:
            return {"error": f"could not launch Ghidra: {exc}"}

        if not output.is_file():
            return {
                "error": "Ghidra did not produce an evidence file",
                "exit_code": proc.returncode,
                "stdout_tail": proc.stdout[-4000:],
                "stderr_tail": proc.stderr[-4000:],
                "target_sha256": snapshot_sha256,
                "target_size": snapshot.stat().st_size,
            }
        try:
            evidence = json.loads(output.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return {"error": f"invalid Ghidra evidence output: {exc}",
                    "stdout_tail": proc.stdout[-2000:],
                    "stderr_tail": proc.stderr[-2000:]}

    evidence.update({
        "tool": "qi-nx-ghidra-evidence",
        "author": "Qi-NX",
        "target": str(path),
        "target_size": snapshot.stat().st_size,
        "target_sha256": snapshot_sha256,
        "ghidra_executable": executable,
        "ghidra_exit_code": proc.returncode,
        "limitations": [
            "static analysis only; the target was not executed",
            "function and call references reflect Ghidra auto-analysis and may be incomplete",
            "addresses include image-relative offsets; validate interpretations against the listing",
        ],
    })
    if proc.returncode != 0:
        evidence["analysis_warning"] = "Ghidra exited with a non-zero status; inspect logs before relying on completeness."
        evidence["stderr_tail"] = proc.stderr[-4000:]
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="binary to analyze statically")
    parser.add_argument("--ghidra", help="path to analyzeHeadless (or set GHIDRA_ANALYZE_HEADLESS)")
    parser.add_argument("--max-functions", type=int, default=5000)
    parser.add_argument("--timeout", type=int, default=900, help="analysis timeout in seconds")
    parser.add_argument("--json", action="store_true", help="emit JSON only")
    args = parser.parse_args()
    result = analyze(args.target, args.ghidra, args.max_functions, args.timeout)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif "error" in result:
        print(result["error"], file=sys.stderr)
        return 2
    else:
        print(f"# ghidra_evidence — {result['target']}\n# {BANNER}")
        print(f"sha256: {result['target_sha256']}  functions: {result['function_total']}  "
              f"calls: {result['callsite_total']}")
        for function in result["functions"][:40]:
            print(f"{function['entry']['image_offset']:>12}  {function['name']}  "
                  f"size={function['size_bytes']} calls={len(function['calls'])}")
        if result.get("truncated"):
            print("output truncated; increase --max-functions to include more functions")
    return 0 if "error" not in result else 2


if __name__ == "__main__":
    sys.exit(main())
