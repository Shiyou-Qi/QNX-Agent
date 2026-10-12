---
name: reverse-engineering
description: >-
  Qi-NX-Agent playbook for binaries, firmware, packed loaders, and network
  protocols. Load before analysing an unknown artifact. Copyright Qi-NX.
---

# Qi-NX-Agent — Reverse-engineering playbook

## 0.1 Preferred entry points: MCP first, scripts as fallback

The Qi-NX UEFI MCP server exposes the triage helpers (and the firmware toolkit)
as `mcp__uefi__*` tools. Prefer them; they return structured JSON.

| MCP tool | Script equivalent | Purpose |
|---|---|---|
| `mcp__uefi__tool_status` | — | which Python modules / external binaries are really available |
| `mcp__uefi__lief_info` | `lief_info.py` | PE / ELF / Mach-O metadata, sections, imports, exports |
| `mcp__uefi__pack_detect` | `pack_detect.py` | packer / VMProtect / Themida fingerprint via section name + entropy + import shape |
| `mcp__uefi__yara_scan` | `yara_scan.py` | built-in packer / crypto / IOC rules; `rules=<dir>` plugs in your own ruleset |
| `mcp__uefi__binwalk_scan` | internal signatures | magic + compression offsets for container triage |
| `mcp__uefi__walk_fv`, `extract_vss`, `parse_vss`, `list_smi` | firmware scripts | firmware / UEFI work (see the `firmware-uefi` skill) |

Script fallback, when MCP is unavailable:
`python .dsh/skills/reverse-engineering/scripts/<tool>.py <args>`.
Every script accepts `--json` and returns the same structure as its MCP tool.

Install the optional heavy dependencies once per host:

```
python -m pip install lief yara-python
```

The YARA built-in ruleset deduplicates overlapping matches, so one `192.168.10.44`
yields one hit rather than one per start offset.

All scripts and the MCP server print `by Qi-NX-Agent (Copyright Qi-NX)`.

## 0. Rules of engagement

- Default to read-only analysis. Only run an unknown sample inside a VM or sandbox isolated from production data.
- Record questions, hypotheses, and evidence in one running notes file (`<artifact>.notes.md`) as you go.
- Always compute and log SHA-256 of every input before analysis; reuse it as the canonical artifact id.

## 1. Triage

1. Identify container and architecture:
   - `file <bin>`, `xxd -l 64 <bin>`, `binwalk -E <bin>`, `diec <bin>` / `DetectItEasy`, `peid`, `osslsigncode verify`.
   - On Linux: `readelf -h`, `objdump -f`, `ldd`, `strings -a -n 6 -t x`.
   - On Windows PE: `pestudio`, `pe-sieve`, `dumpbin /headers /imports`.
2. Detect packing / encryption:
   - High entropy sections + tiny import table ⇒ packed (UPX, Themida, VMProtect, custom).
   - Check known packer IDs via DIE or `peid`.
3. Extract quick IOCs:
   - URLs, IPs, mutexes, user-agents, file paths, registry keys.
   - `strings -a -n 6 -e l` for UTF-16LE; bulk extractor for bulk features.

## 2. Static analysis

- Disassemble:
  - IDA Pro / Ghidra / Binary Ninja for full PE/ELF/Mach-O; radare2 (`r2 -A`, `pdf`, `aaa`) for scripted work.
  - Always dump `.text` with `objdump -d -M intel` for cross-checks.
- Recover imports and resolve API calls; note unpacked-thunk patterns.
- Cross-reference strings → code; build the call graph around interesting strings.
- For .NET: dnSpy / ILSpy. For Java: jadx / CFR. For Delphi: IDR.
- For Python-compiled: pyinstxtractor, uncompyle6 / decompyle3 / pycdc.

## 3. Dynamic analysis (sandbox only!)

- Pick debugger:
  - Windows ring3: x64dbg + ScyllaHide, WinDbg Preview, OllyDbg (legacy).
  - Windows kernel: WinDbg + VMware/VirtualBox stub.
  - Linux: gdb + gef/pwndbg, lldb, strace/ltrace.
  - Instrumentation: Frida, DynamoRIO, Intel Pin.
- Watch imports of interest: crypto (Crypt*), network (send/recv/WSA*), file IO (CreateFile/WriteFile), process injection (OpenProcess/WriteProcessMemory/CreateRemoteThread).
- Capture traffic: Wireshark/mitmproxy/Fiddler with verdict logging.
- Snapshot the VM before any execution.

## 4. Unpacking

- Hardware breakpoints on write to locate OEP; typical packer pattern: pushad → ... → popad → jmp OEP.
- Dump with Scylla / PETools / lordpe; rebuild IAT.
- For Themida/VMProtect: use a VM-tracer or snapshot diffing; resist the urge to manually de-virtualize.
- For script-packers (pyinstaller, autoit, innosetup): use the dedicated extractor before static analysis.

## 5. Crypto & obfuscation

- Identify algorithms via constants: AES S-box, SHA-2 K constants, RC4 KSA, CRC tables; `findcrypt`, `IDA Signsrch`, `yara rules`.
- Custom encodings: look for XOR/ROL/ROR loops; test base64/base58/base85 with CyberChef.
- String obfuscation: search for a single decoder function called with different keys; rewrite decoder in Python or use the debugger to dump decoded strings.

## 6. Protocol reversing

- Capture with Wireshark; carve streams with `tcpflow` / `pcapfix` / mitmproxy.
- Identify framing: length-prefix, magic bytes, message-type, sequence numbers, CRC.
- Replay a known-good packet and bit-flip fields; observe responses to map the grammar.
- Write a dissector in Python (scapy) or Wireshark Lua.

## 7. Reporting

- Produce: executive summary, artifact manifest (md5/sha1/sha256, size, type), IOC table, MITRE ATT&CK mapping, capability breakdown, recommended detections (yara, sigma, suricata), and a confidence rating per claim.

## 8. Subagent fan-out pattern

For work items longer than ~5 static passes or with independent threads (e.g. one thread unpacks while another parses a C2 protocol), dispatch a `subagent` per thread with a tightly-scoped brief. The parent keeps the running notes file and synthesises findings; children return string/IOC tables and address maps.

## 9. Tool-friendly formats

- Dumps: produce `.id0/.id1`, `.gpr`, `.i64` where applicable; otherwise export `objdump` listings and radare2 projects.
- Patch: emit unified diff against the original bytes; include both offset and RVA.
- Pseudocode: C99 with explicit widths (`uint32_t`); name locals after observations, not generically.
