#!/usr/bin/env python3
"""Qi-NX UEFI MCP server — protocol conformance test.

Speaks newline-delimited JSON-RPC over stdio, which is the MCP stdio transport,
so this test does not depend on any client-side SDK API (and therefore cannot
silently pass by using a different client version than DSH does).

Usage:
    python tests/test_mcp_protocol.py [fixture.bin]

Exit code 0 = every check passed; 1 = at least one check failed. Uses
`sys.executable` to spawn the server so it runs under the same interpreter as
this test (which is where `mcp`, `lief`, `yara` must be installed).
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SERVER = REPO / "dsh-uefi-mcp" / "server" / "uefi_mcp_server.py"

EXPECTED_TOOLS = {
    "tool_status", "walk_fv", "extract_vss", "parse_vss", "list_smi",
    "uefi_firmware_parse", "binwalk_scan", "uefitool_extract",
    "lief_info", "yara_scan", "pack_detect",
}


class McpError(RuntimeError):
    pass


def _spawn() -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, str(SERVER)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", bufsize=1,
    )


def main() -> int:
    fixture = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    if fixture is None or not fixture.is_file():
        print(f"usage: {sys.argv[0]} <fixture.bin>  (build one with tests/fixtures.py)")
        return 2

    if not SERVER.is_file():
        print(f"server not found: {SERVER}")
        return 2

    proc = _spawn()
    stderr_lines: list[str] = []
    threading.Thread(
        target=lambda: [stderr_lines.append(ln.rstrip()) for ln in proc.stderr],
        daemon=True,
    ).start()

    failures: list[str] = []

    def send(obj: dict) -> None:
        proc.stdin.write(json.dumps(obj) + "\n")
        proc.stdin.flush()

    def read_response(want_id, timeout: float = 90.0) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                raise McpError("server closed stdout")
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                raise McpError(f"non-JSON on stdout (protocol violation): {line[:200]!r}")
            if msg.get("id") == want_id:
                return msg
        raise McpError(f"no response for id={want_id}")

    def call_tool(name: str, arguments: dict, call_id: int) -> dict:
        send({"jsonrpc": "2.0", "id": call_id, "method": "tools/call",
              "params": {"name": name, "arguments": arguments}})
        resp = read_response(call_id)
        content = resp.get("result", {}).get("content", [])
        text = content[0].get("text", "") if content else ""
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"_raw": text}

    def check(name: str, ok: bool, detail: str = "") -> None:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail and not ok else ""))
        if not ok:
            failures.append(name)

    try:
        # --- handshake -----------------------------------------------------
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2026-07-28",
            "capabilities": {},
            "clientInfo": {"name": "qinx-conformance", "version": "1.0"},
        }})
        result = read_response(1).get("result", {})
        check("initialize returns a result", bool(result))
        check("serverInfo.name == qinx-uefi",
              result.get("serverInfo", {}).get("name") == "qinx-uefi",
              str(result.get("serverInfo")))
        check("a protocol version is negotiated",
              bool(result.get("protocolVersion")), str(result.get("protocolVersion")))
        check("tools capability is advertised",
              "tools" in (result.get("capabilities") or {}))
        print(f"     negotiated protocolVersion={result.get('protocolVersion')}")

        send({"jsonrpc": "2.0", "method": "notifications/initialized"})

        # --- tool catalog --------------------------------------------------
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tools = read_response(2).get("result", {}).get("tools", [])
        names = sorted(t["name"] for t in tools)
        print(f"     tools: {names}")
        check("all expected tools are listed",
              EXPECTED_TOOLS.issubset(set(names)),
              f"missing={sorted(EXPECTED_TOOLS - set(names))}")
        check("no tool name carries a trailing underscore",
              not any(n.endswith("_") for n in names))
        check("every tool has a description",
              all(t.get("description") for t in tools))

        # --- tool_status ---------------------------------------------------
        status = call_tool("tool_status", {}, 3)
        check("tool_status is callable", bool(status) and "_raw" not in status)
        check("tool_status reports external binaries",
              "external_binaries" in status)
        check("tool_status reports python modules",
              "python_modules" in status)

        # --- walk_fv -------------------------------------------------------
        wf = call_tool("walk_fv", {"image": str(fixture)}, 4)
        check("walk_fv finds one firmware volume",
              len(wf.get("firmware_volumes", [])) == 1,
              str(len(wf.get("firmware_volumes", []))))
        check("walk_fv finds three FFS files", wf.get("file_total") == 3,
              str(wf.get("file_total")))
        check("walk_fv flags one SMM module", wf.get("smm_file_total") == 1,
              str(wf.get("smm_file_total")))

        # --- parse_vss -----------------------------------------------------
        pv = call_tool("parse_vss", {"image": str(fixture)}, 5)
        found = sorted(v["name"] for v in pv.get("variables", []))
        check("parse_vss decodes four variables", len(found) == 4, str(found))
        check("parse_vss flags SecureBoot as sensitive",
              any(v["name"] == "SecureBoot" and v["sensitive"]
                  for v in pv.get("variables", [])))

        # --- binwalk_scan (documents its fallback) -------------------------
        bw = call_tool("binwalk_scan", {"image": str(fixture)}, 6)
        check("binwalk_scan identifies its scanner", "scanner" in bw or "error" in bw)
        check("binwalk_scan reports the _FVH signature",
              any(h["signature"].startswith("uefi-firmware-volume")
                  for h in bw.get("hits", [])),
              str([h["signature"] for h in bw.get("hits", [])][:6]))

        # --- error path ----------------------------------------------------
        err = call_tool("walk_fv", {"image": "Z:/definitely-not-here.bin"}, 7)
        check("a missing file yields a structured error", "error" in err)

    except McpError as exc:
        check(f"protocol exchange completed ({exc})", False)
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()

    if stderr_lines:
        print("\n--- server stderr (first 8 lines) ---")
        for line in stderr_lines[:8]:
            print("   ", line)

    print()
    if failures:
        print(f"RESULT: {len(failures)} check(s) FAILED -> {failures}")
        return 1
    print("RESULT: all MCP protocol checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
