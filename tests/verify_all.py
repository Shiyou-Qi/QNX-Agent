#!/usr/bin/env python3
"""Qi-NX toolkit verification — one command, reproducible checks.

Run with the interpreter that has the dependencies installed:

    <python> tests/verify_all.py

Covers:
  1. every script compiles and answers --help
  2. the firmware parsers agree with a hand-built fixture's known-good values
  3. the extract -> parse chain is equivalent to parsing the whole image
  4. the MCP server passes protocol conformance over stdio

Checks assert exact offsets, sizes, GUIDs, attributes and marker sets, so a
regression in the parsers fails loudly instead of quietly returning less data.

Exit code 0 = all checks passed; 1 = at least one failed.
"""
from __future__ import annotations

import json
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FW_SCRIPTS = REPO / ".dsh" / "skills" / "firmware-uefi" / "scripts"
RE_SCRIPTS = REPO / ".dsh" / "skills" / "reverse-engineering" / "scripts"
ARTIFACTS = REPO / "tests" / "artifacts"

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fixtures  # noqa: E402


class Checker:
    def __init__(self) -> None:
        self.passed = 0
        self.failed: list[str] = []
        self.skipped: list[str] = []

    def check(self, name: str, ok: bool, detail: object = "") -> bool:
        if ok:
            self.passed += 1
            print(f"  [PASS] {name}")
        else:
            self.failed.append(name)
            print(f"  [FAIL] {name}" + (f" — {detail}" if detail != "" else ""))
        return ok

    def skip(self, name: str, why: str) -> None:
        self.skipped.append(f"{name} ({why})")
        print(f"  [SKIP] {name} — {why}")

    def section(self, title: str) -> None:
        print(f"\n=== {title} ===")


def run_json(script: Path, *args: str) -> dict:
    """Run a Qi-NX script with --json and return the parsed result.

    On any failure the returned dict carries an `error` key — the same key the
    scripts use for their own failures — so callers can test `"error" not in r`
    uniformly for both crash and refusal.
    """
    proc = subprocess.run(
        [sys.executable, str(script), *args, "--json"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=300,
    )
    if proc.returncode != 0:
        return {"error": f"exit {proc.returncode}", "_stderr": proc.stderr[-800:]}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return {"error": f"non-JSON output: {exc}", "_stdout": proc.stdout[:400]}


def find_real_binary() -> Path | None:
    """A genuine PE/ELF to exercise the LIEF-based tools against."""
    for cand in (Path(r"C:\Windows\System32\kernel32.dll"),
                 Path("/bin/ls"), Path("/usr/bin/ls")):
        if cand.is_file():
            return cand
    return None


def main() -> int:
    chk = Checker()

    if ARTIFACTS.exists():
        shutil.rmtree(ARTIFACTS)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    chk.section("1. every script compiles and answers --help")
    all_scripts = sorted(
        p for d in (FW_SCRIPTS, RE_SCRIPTS) for p in d.glob("*.py")
        if p.name != "__init__.py"
    )
    for script in all_scripts:
        proc = subprocess.run(
            [sys.executable, "-c",
             f"import py_compile; py_compile.compile(r'{script}', doraise=True)"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        chk.check(f"{script.name}: compiles", proc.returncode == 0,
                  (proc.stderr.strip().splitlines() or [""])[-1])

    for script in all_scripts:
        proc = subprocess.run(
            [sys.executable, str(script), "--help"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=60,
        )
        chk.check(f"{script.name}: --help", proc.returncode == 0)

    # ------------------------------------------------------------------ #
    chk.section("2. fixture")
    fixture_path = ARTIFACTS / "fixture.bin"
    meta = fixtures.build_firmware_image(fixture_path)
    exp = fixtures.FIXTURE_EXPECTATIONS
    chk.check("fixture written", fixture_path.is_file() and meta["size"] > 0,
              f"{meta['size']} bytes")

    # ------------------------------------------------------------------ #
    chk.section("3. walk_fv: PI structures and section extraction")
    ex_dir = ARTIFACTS / "extracted"
    wf = run_json(FW_SCRIPTS / "walk_fv.py", str(fixture_path), "--extract", str(ex_dir))
    if "error" in wf:
        chk.check("walk_fv produced JSON", False, wf)
    else:
        fvs = wf.get("firmware_volumes", [])
        chk.check("one firmware volume", len(fvs) == exp["fv_count"], len(fvs))
        if fvs:
            fv = fvs[0]
            chk.check("FV HeaderLength honoured",
                      fv.get("header_length") == exp["fv_header_length"],
                      fv.get("header_length"))
            chk.check("FV Revision parsed", fv.get("revision") == 2, fv.get("revision"))
            guids = [f["guid"] for f in fv.get("files", [])]
            chk.check("DRIVER file GUID", exp["driver_guid"] in guids, guids)
            chk.check("MM file GUID", exp["mm_guid"] in guids, guids)
            chk.check("VSS file GUID", exp["vss_guid"] in guids, guids)
            mm = next((f for f in fv.get("files", []) if f["guid"] == exp["mm_guid"]), None)
            chk.check("MM module type name is MM_STANDALONE",
                      mm is not None and mm.get("type_name") == "MM_STANDALONE",
                      mm.get("type_name") if mm else "not found")
            chk.check("MM module flagged SMM", bool(mm and mm.get("is_smm")))
        chk.check("three FFS files", wf.get("file_total") == exp["file_total"],
                  wf.get("file_total"))
        chk.check("three sections", wf.get("section_total") == exp["section_total"],
                  wf.get("section_total"))
        chk.check("one SMM module", wf.get("smm_file_total") == exp["smm_file_total"],
                  wf.get("smm_file_total"))
        extracted = wf.get("extracted", [])
        chk.check("exactly one PE32 extracted", len(extracted) == 1, len(extracted))
        if extracted:
            chk.check("PE32 size matches the stub",
                      extracted[0]["size"] == exp["pe32_stub_size"],
                      extracted[0]["size"])
            chk.check("extraction records source FFS and FV offsets",
                      bool(extracted[0].get("source_ffs_offset"))
                      and bool(extracted[0].get("source_fv_offset")),
                      extracted[0])
            chk.check("extraction includes SHA-256 provenance",
                      isinstance(extracted[0].get("sha256"), str)
                      and len(extracted[0]["sha256"]) == 64)
            p = Path(extracted[0]["path"])
            chk.check("extracted file exists with MZ magic",
                      p.is_file() and p.read_bytes()[:2] == b"MZ")

    # ------------------------------------------------------------------ #
    chk.section("4. extract_vss: locate, validate, carve")
    vss_dir = ARTIFACTS / "vss"
    ev = run_json(FW_SCRIPTS / "extract_vss.py", str(fixture_path), "--out", str(vss_dir))
    carved_path = None
    if "error" in ev:
        chk.check("extract_vss produced JSON", False, ev)
    else:
        cands = ev.get("candidates", [])
        chk.check("one candidate store", len(cands) == 1, len(cands))
        if cands:
            c = cands[0]
            chk.check("all four variables validated",
                      c.get("variables_validated") == exp["variable_count"],
                      c.get("variables_validated"))
            chk.check("candidate confidence medium", c.get("confidence") == "medium",
                      c.get("confidence"))
            chk.check("detected via the FFS body", c.get("reason") == "ffs-body",
                      c.get("reason"))
            carved_path = Path(c["carved_path"])
            chk.check("carved blob exists", carved_path.is_file())
            chk.check("variable headers located past the store header",
                      c.get("variable_headers_at") not in (None, c.get("offset")),
                      f"store={c.get('offset')} vars={c.get('variable_headers_at')}")

    # ------------------------------------------------------------------ #
    chk.section("5. parse_vss: variable decoding (image and carved blob)")
    pv = run_json(FW_SCRIPTS / "vss_parse.py", str(fixture_path))
    if "error" in pv:
        chk.check("vss_parse produced JSON", False, pv)
        names_image = []
    else:
        names_image = sorted(v["name"] for v in pv.get("variables", []))
        chk.check("four variables decoded", len(names_image) == exp["variable_count"],
                  names_image)
        chk.check("variable names match the fixture",
                  names_image == exp["variable_names"], names_image)
        by_name = {v["name"]: v for v in pv.get("variables", [])}
        pk = by_name.get("PK", {})
        chk.check("PK attributes == 0x27 (TIME_AUTH set)",
                  pk.get("attributes") == hex(exp["pk_attributes"]),
                  pk.get("attributes"))
        chk.check("PK flagged sensitive", bool(pk.get("sensitive")))
        boot = by_name.get("BootOrder", {})
        chk.check("BootOrder attributes decoded as NV+BS+RT",
                  set(boot.get("attributes_names", [])) == {"NV", "BS", "RT"},
                  boot.get("attributes_names"))
        chk.check("Setup data size matches the fixture",
                  by_name.get("Setup", {}).get("size") == len(fixtures.VARIABLES["Setup"][0]),
                  by_name.get("Setup", {}).get("size"))

    if carved_path and carved_path.is_file():
        pvc = run_json(FW_SCRIPTS / "vss_parse.py", str(carved_path))
        if "error" in pvc:
            chk.check("vss_parse on the carved blob", False, pvc)
        else:
            names_carved = sorted(v["name"] for v in pvc.get("variables", []))
            chk.check("carve -> parse equals parse-in-place", names_carved == names_image,
                      f"image={names_image} carved={names_carved}")
    else:
        chk.skip("carve -> parse equivalence", "no carved blob")

    # ------------------------------------------------------------------ #
    chk.section("6. list_smi: Ring -2 enumeration")
    ls = run_json(FW_SCRIPTS / "list_smi.py", str(fixture_path))
    if "error" in ls:
        chk.check("list_smi produced JSON", False, ls)
    else:
        chk.check("firmware-image mode", ls.get("mode") == "firmware-image",
                  ls.get("mode"))
        mods = ls.get("modules", [])
        chk.check("one SMM module found", len(mods) == 1, len(mods))
        if mods:
            m = mods[0]
            chk.check("module GUID matches", m.get("guid") == exp["mm_guid"], m.get("guid"))
            chk.check("module is an SMM FFS type", bool(m.get("is_smm_ffs_type")))
            found = set(m.get("marker_names", []))
            chk.check("all SMM dispatch markers recovered",
                      set(exp["smm_markers"]).issubset(found),
                      f"missing={sorted(set(exp['smm_markers']) - found)}")

    # ------------------------------------------------------------------ #
    chk.section("7. uefi_walk: fallback scanner agrees on the type table")
    uw_extract = ARTIFACTS / "uefi-walk-extracted"
    uw = run_json(FW_SCRIPTS / "uefi_walk.py", str(fixture_path),
                  "--extract", str(uw_extract))
    if "error" in uw:
        chk.check("uefi_walk produced JSON", False, uw)
    else:
        chk.check("FFS total is three", uw.get("ffs_total") == exp["file_total"],
                  uw.get("ffs_total"))
        blob = json.dumps(uw)
        for expected_type in ("DRIVER", "MM_STANDALONE", "RAW"):
            chk.check(f"uefi_walk reports {expected_type}", expected_type in blob)
        extracted_files = list(uw_extract.rglob("*")) if uw_extract.exists() else []
        chk.check("uefi_walk --extract writes PE32/TE payloads",
                  any(p.is_file() for p in extracted_files), extracted_files)

    # ------------------------------------------------------------------ #
    chk.section("8. triage tools on a real binary")
    real = find_real_binary()
    if real is None:
        chk.skip("lief_info / pack_detect on a real binary", "no PE or ELF on this host")
    else:
        li = run_json(RE_SCRIPTS / "lief_info.py", str(real), "--sections")
        chk.check(f"lief_info parses {real.name}", "error" not in li,
                  li.get("error"))
        chk.check("lief_info reports a format", bool(li.get("format")), li.get("format"))
        chk.check("lief_info reports an architecture", li.get("arch") not in (None, "?"),
                  li.get("arch"))
        chk.check("lief_info reports a sha256",
                  isinstance(li.get("sha256"), str) and len(li.get("sha256", "")) == 64)
        if "sections" in li:
            chk.check("lief_info returns sections",
                      len(li["sections"]) > 0, len(li.get("sections", [])))

        pd = run_json(RE_SCRIPTS / "pack_detect.py", str(real))
        chk.check("pack_detect parses the binary", "error" not in pd, pd.get("error"))
        chk.check("pack_detect emits a verdict", bool(pd.get("verdict")),
                  pd.get("verdict"))
        chk.check("pack_detect emits a confidence note", bool(pd.get("confidence")))
        chk.check("pack_detect lists evidence and limitations",
                  "evidence" in pd and bool(pd.get("limitations")))

    # ------------------------------------------------------------------ #
    chk.section("9. yara_scan: rule compilation and overlap dedup")
    if importlib.util.find_spec("yara") is None:
        chk.skip("YARA rule compilation and overlap checks", "yara-python not installed")
    else:
        ys = run_json(RE_SCRIPTS / "yara_scan.py", str(fixture_path))
        chk.check("yara_scan compiles the built-in ruleset", "error" not in ys,
                  ys.get("error"))
        chk.check("yara_scan reports an integer match_total",
                  isinstance(ys.get("match_total"), int), ys.get("match_total"))

        # A file engineered to hit several rules at overlapping offsets.
        control = ARTIFACTS / "yara-control.bin"
        control.write_bytes(
            b"UPX0 http://evil.example.com/payload.bin 192.168.10.44 999.999.999.999 "
            b"admin@evil.example.com ASPack"
        )
        ysc = run_json(RE_SCRIPTS / "yara_scan.py", str(control))
        hits = ysc.get("matches", [])
        ip_hits = [h for h in hits if h["rule"] == "qi_nx_ioc_ipv4"]
        mail_hits = [h for h in hits if h["rule"] == "qi_nx_ioc_email"]
        chk.check("overlapping IPv4 matches deduplicated to one",
                  len(ip_hits) == 1, len(ip_hits))
        chk.check("invalid IPv4 octets do not match the built-in IOC rule",
                  "999.999.999.999" not in [h["preview_text"] for h in ip_hits],
                  [h["preview_text"] for h in ip_hits])
        chk.check("overlapping email matches deduplicated to one",
                  len(mail_hits) == 1, len(mail_hits))
        chk.check("packer rules hit on the control",
                  any(h["rule"] == "qi_nx_packer_upx" for h in hits)
                  and any(h["rule"] == "qi_nx_packer_aspack" for h in hits),
                  [h["rule"] for h in hits])

    # ------------------------------------------------------------------ #
    chk.section("10. chipsec_abstract: log normalisation")
    log = ARTIFACTS / "chipsec.log"
    log.write_text(
        "[*] running module: common.bios_wp\n"
        "[+] BIOS Region Write Protection is enabled\n"
        "[!] BIOSWE bit is set\n"
        "[*] running module: common.spi_lock\n"
        "[!] SPI controller is not locked\n"
        "[CHIPSEC] CONFIGURED\n"
    )
    ca = run_json(FW_SCRIPTS / "chipsec_abstract.py", str(log))
    mods = ca.get("modules", [])
    chk.check("chipsec log parsed into modules", len(mods) >= 2, len(mods))
    statuses = [r["status"] for m in mods for r in m.get("results", [])]
    chk.check("FAIL status extracted from [!] lines", "FAIL" in statuses, statuses)
    chk.check("PASS status extracted from [+] lines", "PASS" in statuses, statuses)

    # ------------------------------------------------------------------ #
    chk.section("11. MCP server protocol conformance")
    edge_case_test = Path(__file__).resolve().parent / "test_edge_cases.py"
    edge_proc = subprocess.run(
        [sys.executable, str(edge_case_test)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=120,
    )
    chk.check("nested FV and variable-state edge cases passed",
              edge_proc.returncode == 0,
              (edge_proc.stdout + edge_proc.stderr)[-800:])

    # ------------------------------------------------------------------ #
    chk.section("12. MCP server protocol conformance")
    mcp_test = Path(__file__).resolve().parent / "test_mcp_protocol.py"
    proc = subprocess.run(
        [sys.executable, str(mcp_test), str(fixture_path)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=600,
    )
    tail = [ln for ln in proc.stdout.splitlines() if ln.strip()][-14:]
    for line in tail:
        print("   ", line)
    chk.check("MCP conformance suite passed", proc.returncode == 0,
              f"exit {proc.returncode}")
    if proc.returncode != 0 and proc.stderr.strip():
        print("    stderr:", proc.stderr.strip()[-600:])

    # ------------------------------------------------------------------ #
    print("\n" + "=" * 58)
    print(f"passed: {chk.passed}   failed: {len(chk.failed)}   skipped: {len(chk.skipped)}")
    if chk.skipped:
        for s in chk.skipped:
            print(f"  skipped: {s}")
    if chk.failed:
        print("\nfailures:")
        for f in chk.failed:
            print(f"  - {f}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
