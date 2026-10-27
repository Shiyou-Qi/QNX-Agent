#!/usr/bin/env python3
"""Qi-NX UEFI MCP server — firmware / UEFI reverse-engineering tools over MCP.

Exposes the Qi-NX firmware toolkit (and the LIEF/YARA helpers) as MCP tools so a
DSH agent can call them as `mcp__uefi__<tool>` without shelling out.

Design notes
------------
* Official `mcp` Python SDK (`mcp.server.mcpserver.MCPServer`). The SDK's latest
  protocol revision is 2026-07-28, which is what the DSH MCP client prefers.
* stdio transport: **nothing** may be written to stdout except JSON-RPC. All
  diagnostics go to stderr.
* Blocking file work runs in a worker thread so the server stays responsive to
  protocol traffic and cancellation.
* Tools that need an external binary (binwalk, UEFIExtract) report its absence
  instead of pretending to succeed, and fall back to the dependency-free
  implementation where one exists.

Banner: by QNX-Agent (Copyright Qi-NX)
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

BANNER = "by QNX-Agent (Copyright Qi-NX)"

# --------------------------------------------------------------------------- #
# Locate the Qi-NX script modules (firmware toolkit + LIEF/YARA helpers).
# --------------------------------------------------------------------------- #


def _workspace_root() -> Path:
    """Return the workspace that contains this bundle.

    The server lives at `<workspace>/dsh-uefi-mcp/server/uefi_mcp_server.py`, so
    the workspace is two levels up. Deriving it from `__file__` keeps this bundle
    free of machine-specific absolute paths while still needing no configuration
    when it sits inside the workspace it serves.
    """
    return Path(__file__).resolve().parents[2]


# Skill script trees, relative to the workspace root.
DEFAULT_SCRIPT_DIRS = {
    "fw_scripts": Path(".dsh") / "skills" / "firmware-uefi" / "scripts",
    "re_scripts": Path(".dsh") / "skills" / "reverse-engineering" / "scripts",
    "android_scripts": Path(".dsh") / "engines" / "android-apk",
}

# Optional override file beside the bundle. Not required, and not shipped with
# any absolute paths: set the QINX_* environment variables instead if the bundle
# lives outside the workspace it serves.
_PATHS_FILE = "_paths.local.json"


def _resolve_script_dirs() -> dict[str, Path]:
    """Resolve the Qi-NX script directories.

    Precedence: `QINX_*_SCRIPTS` environment variables, then
    an optional `_paths.local.json` beside the bundle, then the self-located
    default under the workspace that contains this bundle.
    """
    workspace = _workspace_root()
    cfg_path = Path(__file__).resolve().parent.parent / _PATHS_FILE

    cfg: dict = {}
    if cfg_path.is_file():
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            print(f"qinx-uefi-mcp: unreadable {cfg_path}: {exc}", file=sys.stderr)

    resolved: dict[str, Path] = {}
    for key, env in (("fw_scripts", "QINX_FW_SCRIPTS"),
                     ("re_scripts", "QINX_RE_SCRIPTS"),
                     ("android_scripts", "QINX_ANDROID_SCRIPTS")):
        raw = os.environ.get(env) or cfg.get(key)
        resolved[key] = Path(raw) if raw else (workspace / DEFAULT_SCRIPT_DIRS[key])
    return resolved


DIRS = _resolve_script_dirs()
for _key, _dir in DIRS.items():
    if _dir.is_dir():
        sys.path.insert(0, str(_dir))
    else:
        print(f"qinx-uefi-mcp: {_key} is not a directory: {_dir}", file=sys.stderr)

# Imported after sys.path is prepared.
import walk_fv            # noqa: E402
import extract_vss        # noqa: E402
import vss_parse          # noqa: E402
import list_smi           # noqa: E402
import firmware_diff      # noqa: E402

try:
    import lief_info      # noqa: E402
except Exception as exc:  # noqa: BLE001
    lief_info = None
    print(f"qinx-uefi-mcp: lief_info unavailable: {exc}", file=sys.stderr)

try:
    import yara_scan      # noqa: E402
except Exception as exc:  # noqa: BLE001
    yara_scan = None
    print(f"qinx-uefi-mcp: yara_scan unavailable: {exc}", file=sys.stderr)

try:
    import pack_detect    # noqa: E402
except Exception as exc:  # noqa: BLE001
    pack_detect = None
    print(f"qinx-uefi-mcp: pack_detect unavailable: {exc}", file=sys.stderr)

try:
    import ghidra_evidence  # noqa: E402
except Exception as exc:  # noqa: BLE001
    ghidra_evidence = None
    print(f"qinx-uefi-mcp: ghidra_evidence unavailable: {exc}", file=sys.stderr)

try:
    import yara_backtest  # noqa: E402
except Exception as exc:  # noqa: BLE001
    yara_backtest = None
    print(f"qinx-uefi-mcp: yara_backtest unavailable: {exc}", file=sys.stderr)

try:
    import dynamic_evidence  # noqa: E402
except Exception as exc:  # noqa: BLE001
    dynamic_evidence = None
    print(f"qinx-uefi-mcp: dynamic_evidence unavailable: {exc}", file=sys.stderr)

try:
    import security_assessment  # noqa: E402
except Exception as exc:  # noqa: BLE001
    security_assessment = None
    print(f"qinx-uefi-mcp: security_assessment unavailable: {exc}", file=sys.stderr)

try:
    import vulnerability_scan  # noqa: E402
except Exception as exc:  # noqa: BLE001
    vulnerability_scan = None
    print(f"qinx-uefi-mcp: vulnerability_scan unavailable: {exc}", file=sys.stderr)

try:
    import android_apk_analyze  # noqa: E402
except Exception as exc:  # noqa: BLE001
    android_apk_analyze = None
    print(f"qinx-uefi-mcp: android_apk_analyze unavailable: {exc}", file=sys.stderr)

try:
    import android_apk_workflows  # noqa: E402
except Exception as exc:  # noqa: BLE001
    android_apk_workflows = None
    print(f"qinx-uefi-mcp: android_apk_workflows unavailable: {exc}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# Dependency-free firmware signature scan (the binwalk fallback).
# --------------------------------------------------------------------------- #

# (label, needle, weak) — `weak` magics are short/ambiguous and are only
# reported on alignment.
SIGNATURES: list[tuple[str, bytes, bool]] = [
    ("uefi-firmware-volume(_FVH)", b"_FVH", False),
    ("intel-flash-descriptor", b"\x5a\xa5\xf0\x0f", False),
    ("intel-me($FPT)", b"$FPT", False),
    ("gzip", b"\x1f\x8b\x08", False),
    ("xz", b"\xfd7zXZ\x00", False),
    ("bzip2", b"BZh", True),
    ("zstd", b"\x28\xb5\x2f\xfd", False),
    ("lz4-frame", b"\x04\x22\x4d\x18", False),
    ("lzma-alone", b"\x5d\x00\x00", True),
    ("7-zip", b"7z\xbc\xaf\x27\x1c", False),
    ("rar", b"Rar!\x1a\x07", False),
    ("squashfs-le", b"hsqs", False),
    ("squashfs-be", b"sqsh", False),
    ("cramfs", b"\x45\x3d\xcd\x28", False),
    ("ubi", b"UBI#", False),
    ("jffs2-le", b"\x85\x19", True),
    ("jffs2-be", b"\x19\x85", True),
    ("android-boot", b"ANDROID!", False),
    ("fit-or-dtb", b"\xd0\x0d\xfe\xed", False),
    ("elf", b"\x7fELF", False),
    ("pe(MZ)", b"MZ", True),
    ("tiano-custom-decompress-guid", None, False),   # filled below
    ("lzma-custom-decompress-guid", None, False),    # filled below
]

_TIANO_GUIDS = (
    ("tiano-custom-decompress-guid", "A31280AD-481E-41B6-95E8-127F4C984779"),
    ("lzma-custom-decompress-guid", "EE4E5898-3914-4259-9D6E-DC7BD79403CF"),
)


def _wire_guid(canonical: str) -> bytes | None:
    return list_smi.guid_to_wire(canonical)


def _build_signatures() -> list[tuple[str, bytes, bool]]:
    out: list[tuple[str, bytes, bool]] = []
    guid_map = {name: _wire_guid(g) for name, g in _TIANO_GUIDS}
    for label, needle, weak in SIGNATURES:
        if needle is None:
            wire = guid_map.get(label)
            if wire:
                out.append((label, wire, weak))
            continue
        out.append((label, needle, weak))
    return out


SIGNATURE_TABLE = _build_signatures()


def signature_scan(path: Path, max_hits_per_sig: int = 16,
                   max_total: int = 200) -> dict:
    """Scan for firmware/compression magic values without external tools."""
    data = path.read_bytes()
    hits: list[dict] = []
    total = 0
    for label, needle, weak in SIGNATURE_TABLE:
        if not needle or total >= max_total:
            continue
        found = 0
        idx = 0
        while found < max_hits_per_sig and total < max_total:
            i = data.find(needle, idx)
            if i < 0:
                break
            idx = i + 1
            if weak and (i % 4) != 0:
                continue
            hits.append({"signature": label, "offset": hex(i), "weak": weak})
            found += 1
            total += 1
    hits.sort(key=lambda h: int(h["offset"], 16))
    return {
        "attempted": "internal-signature-scan",
        "scanner": "qi-nx internal signatures (binwalk not used)",
        "size": len(data),
        "hit_total": len(hits),
        "signatures_known": len(SIGNATURE_TABLE),
        "hits": hits,
        "limitations": [
            "no entropy analysis and no recursive extraction",
            "install binwalk for full carving (the binwalk_scan tool will use it)",
            "short magics are only reported on 4-byte alignment and flagged weak",
        ],
    }


def _which(name: str) -> str | None:
    return shutil.which(name)


# --------------------------------------------------------------------------- #
# MCP server + tools
# --------------------------------------------------------------------------- #

try:
    from mcp.server.mcpserver import MCPServer
except ImportError:
    # The official SDK exposed FastMCP before MCPServer was available at this
    # import path. Keep the same decorator/run surface across supported releases.
    try:
        from mcp.server.fastmcp import FastMCP

        class MCPServer(FastMCP):
            def __init__(self, name: str, version: str | None = None,
                         instructions: str | None = None):
                # FastMCP 1.x derives its protocol version from the SDK and does
                # not accept the MCPServer 2.x `version` constructor argument.
                super().__init__(name=name, instructions=instructions)
    except ImportError as exc:  # pragma: no cover
        print(f"qinx-uefi-mcp: the `mcp` SDK is required (pip install mcp): {exc}",
              file=sys.stderr)
        raise

server = MCPServer(
    name="qinx-uefi",
    version="1.0.5",
    instructions=(
        "Qi-NX reverse-engineering toolkit for firmware and Android packages. " + BANNER + ".\n"
        "Choose tools from observed evidence: start with tool_status and "
        "android_apk_analyze for APK/APKS/XAPK/AAB static inventory and manifest "
        "candidates; optional JADX/APKTool source inspection, Android doctor, version "
        "comparison, SBOM/CVE scan, and full report tools are available. Dynamic "
        "install/launch requires explicit user authorization and emulator confirmation. "
        "binwalk_scan; use walk_fv when firmware-volume signatures or a BIOS "
        "region are present; use extract_vss/parse_vss when NVRAM is relevant; "
        "use list_smi for MM/SMM leads. If compressed sections appear, decompress "
        "with an available parser and re-walk the extracted output. Use "
        "ghidra_evidence only for a concrete code-path question, yara_backtest "
        "before recommending custom rules, firmware_diff for version comparisons, "
        "and dynamic_evidence only to normalize telemetry exported from an isolated "
        "sandbox. For source/dependency security scans, choose vulnerability_scan: "
        "osv for package advisories, trivy for dependency/config/secret checks, "
        "or semgrep for source rules. security_assessment parses saved reports offline. "
        "Verify scanner findings before calling them confirmed vulnerabilities. Prefer walk_fv "
        "over uefi_walk for PI-structure parsing and PE32/TE extraction. Treat "
        "heuristics and string markers as leads, not final vulnerability verdicts."
    ),
)


async def _in_thread(fn, *args, **kwargs):
    """Run blocking file work off the event loop when anyio is available."""
    try:
        import anyio
    except ImportError:
        return fn(*args, **kwargs)
    return await anyio.to_thread.run_sync(lambda: fn(*args, **kwargs))


def _dumps(obj) -> str:
    return json.dumps(obj, indent=2, default=str)


@server.tool(description="Report which Qi-NX tools, Python modules and external "
                         "binaries are available in this environment.")
async def tool_status() -> str:
    def collect() -> dict:
        def mod(name: str):
            try:
                __import__(name)
                return "available"
            except Exception as e:  # noqa: BLE001
                return f"unavailable ({e.__class__.__name__})"

        return {
            "author": "Qi-NX",
            "script_dirs": {k: str(v) for k, v in DIRS.items()},
            "script_modules": {
                "walk_fv": "available",
                "extract_vss": "available",
                "vss_parse": "available",
                "list_smi": "available",
                "firmware_diff": "available",
                "lief_info": "available" if lief_info else "unavailable",
                "yara_scan": "available" if yara_scan else "unavailable",
                "pack_detect": "available" if pack_detect else "unavailable",
                "ghidra_evidence": "available" if ghidra_evidence else "unavailable",
                "yara_backtest": "available" if yara_backtest else "unavailable",
                "dynamic_evidence": "available" if dynamic_evidence else "unavailable",
                "security_assessment": "available" if security_assessment else "unavailable",
                "vulnerability_scan": "available" if vulnerability_scan else "unavailable",
                "android_apk_analyze": "available" if android_apk_analyze else "unavailable",
                "android_apk_workflows": "available" if android_apk_workflows else "unavailable",
            },
            "python_modules": {
                "lief": mod("lief"),
                "yara": mod("yara"),
                "uefi_firmware": mod("uefi_firmware"),
                "mcp": mod("mcp"),
            },
            "external_binaries": {
                "binwalk": _which("binwalk") or "absent",
                "UEFIExtract": _which("UEFIExtract") or _which("uefitool") or "absent",
                "chipsec_main": _which("chipsec_main") or "absent",
                "analyzeHeadless": ((ghidra_evidence._find_ghidra(None) or "absent")
                                    if ghidra_evidence else "absent"),
                "trivy": _which("trivy") or "absent",
                "osv-scanner": _which("osv-scanner") or "absent",
                "semgrep": _which("semgrep") or "absent",
                "apkanalyzer": (" ".join(android_apk_analyze._tool_command("apkanalyzer") or [])
                                if android_apk_analyze and android_apk_analyze._tool_command("apkanalyzer") else "absent"),
                "aapt2": _which("aapt2") or _which("aapt2.exe") or "absent",
                "apksigner": (" ".join(android_apk_analyze._tool_command("apksigner") or [])
                              if android_apk_analyze and android_apk_analyze._tool_command("apksigner") else "absent"),
                "apktool": (" ".join(android_apk_analyze._tool_command("apktool") or [])
                            if android_apk_analyze and android_apk_analyze._tool_command("apktool") else "absent"),
                "jadx": (" ".join(android_apk_analyze._tool_command("jadx") or [])
                         if android_apk_analyze and android_apk_analyze._tool_command("jadx") else "absent"),
                "adb": _which("adb") or _which("adb.exe") or "absent",
                "frida": _which("frida") or "absent",
                "syft": _which("syft") or "absent",
            },
            "fallbacks": {
                "binwalk_scan": "falls back to the internal signature scan",
                "uefitool_extract": "no fallback; walk_fv --extract covers PE32/TE",
            },
        }

    return _dumps(await _in_thread(collect))


@server.tool(name="walk_fv",
             description="Walk UEFI firmware volumes, FFS files and sections "
                         "(PI-spec parsing, no external dependency). Optionally "
                         "extract PE32/TE sections to a directory.")
async def walk_fv_(image: str, extract_dir: str | None = None,
                   max_files: int = 5000) -> str:
    def run() -> dict:
        p = Path(image)
        if not p.is_file():
            return {"error": f"not a file: {p}"}
        info = walk_fv.walk(p, extract_dir, max_files)
        # Keep the response bounded: section detail is where the bulk lives.
        if len(info["firmware_volumes"]) > 8:
            info["notes"].append(
                f"response truncated to 8 of {len(info['firmware_volumes'])} FVs")
            info["firmware_volumes"] = info["firmware_volumes"][:8]
        return info

    return _dumps(await _in_thread(run))


@server.tool(name="extract_vss",
             description="Carve candidate UEFI NVRAM variable stores (VSS) out of "
                         "an image into a directory, validating each candidate by "
                         "walking its 0x55AA variable headers.")
async def extract_vss_(image: str, out_dir: str, raw_scan: bool = False,
                       size_cap: int = 0x40000) -> str:
    def run() -> dict:
        p = Path(image)
        if not p.is_file():
            return {"error": f"not a file: {p}"}
        return extract_vss.extract(p, out_dir, size_cap, raw_scan)

    return _dumps(await _in_thread(run))


@server.tool(name="parse_vss",
             description="Decode UEFI NVRAM variables from an image or from a "
                         "store carved by extract_vss. Flags sensitive variables "
                         "(SecureBoot, PK/KEK/db/dbx, Setup, Boot####).")
async def parse_vss(image: str, variable: str | None = None) -> str:
    def run() -> dict:
        p = Path(image)
        if not p.is_file():
            return {"error": f"not a file: {p}"}
        return vss_parse.parse(p, variable)

    return _dumps(await _in_thread(run))


@server.tool(name="list_smi",
             description="Enumerate SMM/MM modules (Ring -2) in a firmware image "
                         "or analyse one extracted module, reporting EDK2 dispatch "
                         "and communication markers. Optionally search GUIDs from "
                         "an authoritative Name,GUID CSV such as UEFITool's "
                         "guids.csv.")
async def list_smi_(image: str, guids: str | None = None,
                    include_dxe: bool = False,
                    extract_dir: str | None = None) -> str:
    def run() -> dict:
        p = Path(image)
        if not p.is_file():
            return {"error": f"not a file: {p}"}
        return list_smi.list_smm(p, guids, extract_dir, include_dxe)

    return _dumps(await _in_thread(run))


@server.tool(description="Parse a firmware image with the optional "
                         "`uefi-firmware` library, which handles compressed "
                         "sections that walk_fv reports but does not decompress.")
async def uefi_firmware_parse(image: str, max_objects: int = 400) -> str:
    def run() -> dict:
        p = Path(image)
        if not p.is_file():
            return {"error": f"not a file: {p}"}
        try:
            from uefi_firmware import AutoParser  # type: ignore
        except Exception as e:  # noqa: BLE001
            return {
                "error": "the `uefi-firmware` library is not installed",
                "hint": "python -m pip install uefi-firmware",
                "detail": str(e),
                "fallback": "use walk_fv, which needs no dependency",
            }
        parser = AutoParser(str(p))
        objects = []
        try:
            for obj in parser.parse().iterate_objects():
                if len(objects) >= max_objects:
                    break
                objects.append({
                    "type": obj.get("type"),
                    "guid": obj.get("guid"),
                    "offset": hex(obj.get("offset", 0)),
                    "size": obj.get("size"),
                    "name": obj.get("name"),
                })
        except Exception as e:  # noqa: BLE001
            return {"error": f"uefi_firmware parse failed: {e}", "objects": objects}
        return {
            "tool": "qi-nx-uefi-firmware-parse",
            "author": "Qi-NX",
            "image": str(p),
            "object_total": len(objects),
            "objects": objects,
        }

    return _dumps(await _in_thread(run))


@server.tool(description="Magic/compression signature scan for early firmware "
                         "triage. Uses binwalk when it is installed; otherwise "
                         "falls back to the built-in dependency-free scanner and "
                         "says so.")
async def binwalk_scan(image: str) -> str:
    def run() -> dict:
        p = Path(image)
        if not p.is_file():
            return {"error": f"not a file: {p}"}
        binwalk = _which("binwalk")
        if binwalk:
            try:
                proc = subprocess.run(
                    [binwalk, str(p)],
                    capture_output=True, text=True, timeout=300,
                )
                return {
                    "attempted": "binwalk",
                    "scanner": f"binwalk ({binwalk})",
                    "exit_code": proc.returncode,
                    "stdout": proc.stdout[-20000:],
                    "stderr": proc.stderr[-4000:],
                }
            except Exception as e:  # noqa: BLE001
                return {
                    "attempted": "binwalk",
                    "error": f"binwalk failed: {e}",
                    "fallback": signature_scan(p),
                }
        return signature_scan(p)

    return _dumps(await _in_thread(run))


@server.tool(description="Run UEFIExtract (from UEFITool) to unpack a firmware "
                         "image. Reports a clear error when the binary is absent; "
                         "walk_fv's extract_dir covers PE32/TE extraction without it.")
async def uefitool_extract(image: str, out_dir: str) -> str:
    def run() -> dict:
        p = Path(image)
        if not p.is_file():
            return {"error": f"not a file: {p}"}
        exe = _which("UEFIExtract") or _which("uefiextract")
        if not exe:
            return {
                "error": "UEFIExtract is not installed or not on PATH",
                "hint": "install UEFITool (https://github.com/LongSoft/UEFITool) "
                        "and put UEFIExtract on PATH",
                "fallback": "call walk_fv_ with extract_dir to pull PE32/TE sections",
            }
        out = Path(out_dir).expanduser().resolve()
        if out.exists() and any(out.iterdir()):
            return {"error": f"output directory is not empty: {out}",
                    "hint": "use a fresh directory so the extraction manifest cannot mix artifacts"}
        out.mkdir(parents=True, exist_ok=True)
        try:
            proc = subprocess.run(
                [exe, str(p), "-e", "-o", str(out)],
                capture_output=True, text=True, timeout=1800,
            )
        except Exception as e:  # noqa: BLE001
            return {"error": f"UEFIExtract failed: {e}"}
        extracted_files = []
        manifest_truncated = False
        for item in sorted(out.rglob("*")):
            if not item.is_file() or not item.resolve().is_relative_to(out.resolve()):
                continue
            if len(extracted_files) >= 10000:
                manifest_truncated = True
                break
            digest = hashlib.sha256()
            with item.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1 << 20), b""):
                    digest.update(chunk)
            extracted_files.append({
                "path": str(item),
                "relative_path": str(item.relative_to(out)),
                "size": item.stat().st_size,
                "sha256": digest.hexdigest(),
            })
        return {
            "attempted": "UEFIExtract",
            "scanner": exe,
            "out_dir": str(out),
            "extracted_file_total": len(extracted_files),
            "extracted_files": extracted_files,
            "manifest_truncated": manifest_truncated,
            "exit_code": proc.returncode,
            "stdout": proc.stdout[-8000:],
            "stderr": proc.stderr[-4000:],
        }

    return _dumps(await _in_thread(run))


@server.tool(name="lief_info",
             description="LIEF triage (format, arch, entrypoint, sections, "
                         "imports, exports) for PE/ELF/Mach-O and firmware "
                         "components extracted from an image.")
async def lief_info_(target: str, sections: bool = False, imports: bool = False,
                     exports: bool = False, relocs: bool = False) -> str:
    if lief_info is None:
        return _dumps({"error": "lief_info module unavailable"})

    def run() -> dict:
        return lief_info.info(target, sections, imports, exports, relocs)

    return _dumps(await _in_thread(run))


@server.tool(name="yara_scan",
             description="YARA scan with the built-in Qi-NX triage ruleset "
                         "(packers, crypto constants, IOCs) or your own rule "
                         "file/directory.")
async def yara_scan_(target: str, rules: str | None = None,
                     max_matches: int = 100) -> str:
    if yara_scan is None:
        return _dumps({"error": "yara_scan module unavailable"})

    def run() -> dict:
        return yara_scan.scan(target, rules, max_matches)

    return _dumps(await _in_thread(run))


@server.tool(name="pack_detect",
             description="Packer / protector detection from section names, "
                         "entropy and import-table shape, with a verdict and a "
                         "confidence note.")
async def pack_detect_(target: str) -> str:
    if pack_detect is None:
        return _dumps({"error": "pack_detect module unavailable"})

    def run() -> dict:
        p = Path(target)
        if not p.is_file():
            return {"error": f"not a file: {p}"}
        return pack_detect.detect(p)

    return _dumps(await _in_thread(run))


@server.tool(name="ghidra_evidence", description="Run bounded Ghidra headless static analysis and export an address-linked function inventory and call references. The target is analyzed, never executed. Requires Ghidra analyzeHeadless on PATH or GHIDRA_ANALYZE_HEADLESS.")
async def ghidra_evidence_(target: str, max_functions: int = 5000,
                           timeout_seconds: int = 900) -> str:
    if ghidra_evidence is None:
        return _dumps({"error": "ghidra_evidence module unavailable"})

    def run() -> dict:
        return ghidra_evidence.analyze(target, max_functions=max_functions,
                                       timeout=timeout_seconds)

    return _dumps(await _in_thread(run))


@server.tool(name="yara_backtest", description="Compile YARA rules and scan a bounded sample corpus. Supply an optional JSON manifest with SHA-256-pinned sample paths and per-rule boolean labels to calculate precision, recall, and F1 only on labeled pairs. Samples are read, never executed.")
async def yara_backtest_(corpus: str, rules: str, manifest: str | None = None,
                         max_samples: int = 500, max_file_mb: int = 256,
                         timeout_seconds: int = 30,
                         total_timeout_seconds: int = 900) -> str:
    if yara_backtest is None:
        return _dumps({"error": "yara_backtest module unavailable"})

    def run() -> dict:
        return yara_backtest.backtest(corpus, rules, manifest, max_samples,
                                      max_file_mb, timeout_seconds,
                                      total_timeout_seconds)

    return _dumps(await _in_thread(run))


@server.tool(name="firmware_diff", description="Compare two UEFI firmware images by FV/FFS identity and SHA-256, or compare two extracted payload directories by relative path. Optional extracted directories let you compare decompressed UEFIExtract results. Read-only; differences are not vulnerability verdicts.")
async def firmware_diff_(baseline: str, candidate: str,
                         baseline_extracted: str | None = None,
                         candidate_extracted: str | None = None) -> str:
    def run() -> dict:
        return firmware_diff.compare(baseline, candidate,
                                     baseline_extracted, candidate_extracted)

    return _dumps(await _in_thread(run))


@server.tool(name="dynamic_evidence", description="Normalize up to 2000 events from exported CAPE/Cuckoo JSON, Sysmon JSONL, or Procmon CSV telemetry into a behavior timeline and candidate IOC list. Offline parsing only; does not run samples or control a sandbox.")
async def dynamic_evidence_(source: str, sample_sha256: str | None = None) -> str:
    if dynamic_evidence is None:
        return _dumps({"error": "dynamic_evidence module unavailable"})

    def run() -> dict:
        return dynamic_evidence.normalize(source, sample_sha256)

    return _dumps(await _in_thread(run))


@server.tool(name="android_apk_analyze", description="Run Qi-NX's read-only Android package analysis on an APK/APKS/XAPK/APKM/AAB. Computes hashes, inventories ZIP/DEX/native content, maps candidates to OWASP MASVS/selected MASTG references, and inventories exact Maven metadata. By default it uses bounded Python ZIP/DEX inspection only. Set isolated_tooling_confirmed=true before invoking Android SDK parsers/signature tools on the sample; additionally set deep_analysis=true for JADX/APKTool. OSV network access only when scan_vulnerabilities=true. Does not install or execute the app.")
async def android_apk_analyze_(target: str, max_entries: int = 2000,
                              deep_analysis: bool = False,
                              isolated_tooling_confirmed: bool = False,
                              scan_vulnerabilities: bool = False) -> str:
    if android_apk_analyze is None:
        return _dumps({"error": "android_apk_analyze module unavailable"})

    def run() -> dict:
        try:
            return android_apk_analyze.analyze(target, max_entries=max_entries,
                                               deep_analysis=deep_analysis,
                                               isolated_tooling_confirmed=isolated_tooling_confirmed,
                                               scan_vulnerabilities=scan_vulnerabilities)
        except Exception as exc:  # noqa: BLE001
            return {"error": f"APK analysis failed: {exc.__class__.__name__}",
                    "target": target}

    return _dumps(await _in_thread(run))


@server.tool(name="android_apk_doctor", description="Check Android analysis tool paths/versions, SDK environment, and connected emulator serials. Read-only; does not install or launch an app.")
async def android_apk_doctor_() -> str:
    if android_apk_workflows is None:
        return _dumps({"error": "Android workflow module unavailable"})
    return _dumps(await _in_thread(android_apk_workflows.tool_doctor))


@server.tool(name="android_apk_compare", description="Compare two APK versions by sample hashes, Manifest/configuration, archive members, dependency PURLs, and static finding candidates. No app execution. JADX/APKTool require both deep_analysis=true and isolated_tooling_confirmed=true.")
async def android_apk_compare_(before: str, after: str, deep_analysis: bool = False,
                               isolated_tooling_confirmed: bool = False) -> str:
    if android_apk_workflows is None:
        return _dumps({"error": "Android workflow module unavailable"})
    return _dumps(await _in_thread(android_apk_workflows.compare_apks, before, after,
                                   deep_analysis, isolated_tooling_confirmed))


@server.tool(name="android_dependency_scan", description="Extract exact Maven coordinates from APK META-INF/pom.properties, emit CycloneDX SBOM, and optionally check that SBOM with installed OSV-Scanner. OSV lookup may access public advisory data; enable it explicitly with scan_vulnerabilities=true. APK-only dependency inventory is incomplete for shaded, obfuscated, native, or metadata-free libraries.")
async def android_dependency_scan_(target: str, scan_vulnerabilities: bool = False) -> str:
    if android_apk_analyze is None:
        return _dumps({"error": "android_apk_analyze module unavailable"})
    def run() -> dict:
        result = android_apk_analyze.analyze(target, max_entries=1, deep_analysis=False,
                                             scan_vulnerabilities=scan_vulnerabilities)
        return result.get("dependency_analysis", result)
    return _dumps(await _in_thread(run))


@server.tool(name="android_dynamic_session", description="Authorized, bounded install/launch/logcat observation for one APK on a confirmed disposable Android emulator only. Requires authorized=true, isolated_emulator_confirmed=true, a matching package name, and an emulator-<port> serial. Uses adb install without replace mode so an existing app is not upgraded; launches once. The app remains installed after capture. It does not clear data, root the device, bypass controls, or exercise backend actions. Logs are redacted but may still contain sensitive data.")
async def android_dynamic_session_(apk: str, package_name: str, device_serial: str,
                                   authorized: bool, isolated_emulator_confirmed: bool,
                                   observation_seconds: int = 15) -> str:
    if android_apk_workflows is None:
        return _dumps({"error": "Android workflow module unavailable"})
    return _dumps(await _in_thread(android_apk_workflows.dynamic_emulator_session,
                                   apk, package_name, device_serial, authorized,
                                   isolated_emulator_confirmed, observation_seconds))


@server.tool(name="android_apk_report", description="Generate a complete standalone Markdown APK assessment report with sample identity, coverage, tools, MASVS/MASTG-mapped findings, code/dependency leads, authorization scope, limitations, evidence ledger, and Qi-NX footer. Android sample parsers require isolated_tooling_confirmed=true; JADX/APKTool also require deep_analysis=true. Optionally write to a new output path; existing files are never overwritten. OSV network lookup is separately opt-in.")
async def android_apk_report_(target: str, output_path: str | None = None,
                             language: str = "zh", deep_analysis: bool = False,
                             isolated_tooling_confirmed: bool = False,
                             scan_vulnerabilities: bool = False,
                             dynamic_json: str | None = None,
                             authorization_scope: str = "未由分析引擎记录；需由委托方补充") -> str:
    if android_apk_workflows is None:
        return _dumps({"error": "Android workflow module unavailable"})
    def run() -> dict:
        try:
            return android_apk_workflows.write_report(target, output_path, language,
                                                       deep_analysis, isolated_tooling_confirmed,
                                                       scan_vulnerabilities,
                                                       dynamic_json, authorization_scope)
        except Exception as exc:  # noqa: BLE001
            return {"error": f"report generation failed: {exc.__class__.__name__}"}
    return _dumps(await _in_thread(run))


@server.tool(name="vulnerability_scan", description="Run an installed read-only scanner against a local file or directory, then normalize its findings. Use scanner='osv' for dependency advisories, 'trivy' for dependency/misconfiguration/secret checks, or 'semgrep' for source-code rules. The target is never executed; scanners may access public vulnerability databases or rule registries, so review data handling before scanning confidential code. Output files are created only at the requested new path; a raw report may contain matched secret values.")
async def vulnerability_scan_(target: str, scanner: str,
                              timeout_seconds: int = 900,
                              output_file: str | None = None) -> str:
    if vulnerability_scan is None:
        return _dumps({"error": "vulnerability_scan module unavailable"})

    def run() -> dict:
        try:
            return vulnerability_scan.scan(target, scanner,
                                           timeout_seconds=timeout_seconds,
                                           output_file=output_file)
        except Exception as exc:  # noqa: BLE001
            return {"error": str(exc), "scanner": scanner}

    return _dumps(await _in_thread(run))


@server.tool(name="security_assessment", description="Normalize an existing Trivy, OSV-Scanner, Semgrep JSON, or SARIF report into a bounded evidence ledger with finding IDs, severity counts, target/report hashes, and limitations. Offline parsing only; does not rescan or execute the target.")
async def security_assessment_(report: str, target: str | None = None,
                               target_sha256: str | None = None,
                               scanner: str | None = None) -> str:
    if security_assessment is None:
        return _dumps({"error": "security_assessment module unavailable"})

    def run() -> dict:
        try:
            return security_assessment.assess_file(
                report, target=target, target_sha256=target_sha256, scanner=scanner)
        except Exception as exc:  # noqa: BLE001
            return {"error": str(exc), "report": report}

    return _dumps(await _in_thread(run))


def main() -> int:
    print(f"qinx-uefi-mcp starting — {BANNER}", file=sys.stderr)
    print(f"qinx-uefi-mcp script dirs: "
          f"{ {k: str(v) for k, v in DIRS.items()} }", file=sys.stderr)
    server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())
