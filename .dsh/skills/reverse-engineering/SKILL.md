---
name: reverse-engineering
description: >-
  QNX-Agent playbook for binaries, firmware, packed loaders, and network
  protocols. Load before analysing an unknown artifact. Copyright Qi-NX.
---

# QNX-Agent — Reverse-engineering playbook

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
| `mcp__uefi__ghidra_evidence` | `ghidra_evidence.py` | Ghidra headless function inventory and address-linked call references (static only) |
| `mcp__uefi__yara_backtest` | `yara_backtest.py` | compile rules and measure them against a sample corpus using explicit per-rule labels |
| `mcp__uefi__vulnerability_scan` | `vulnerability_scan.py` | run installed OSV-Scanner, Trivy, or Semgrep on a local path and normalize scanner output |
| `mcp__uefi__security_assessment` | `security_assessment.py` | offline normalization of scanner JSON/SARIF into a finding and evidence ledger |
| `mcp__uefi__walk_fv`, `extract_vss`, `parse_vss`, `list_smi` | firmware scripts | firmware / UEFI work (see the `firmware-uefi` skill) |

Script fallback, when MCP is unavailable:
`python .dsh/skills/reverse-engineering/scripts/<tool>.py <args>`.
Every script accepts `--json` and returns the same structure as its MCP tool.

Install the optional heavy dependencies once per host:

```
python -m pip install lief yara-python
```

Optional external scanners must be installed separately and available on `PATH`:
`osv-scanner` for dependency advisories, `trivy` for dependency/misconfiguration/
secret scans, and `semgrep` for source-code rules. The scanner wrapper passes a
local path as an argument and never launches the target. Depending on scanner
configuration, a scan may contact public vulnerability databases or remote rule
registries. `security_assessment.py` is offline and parses saved JSON/SARIF.

The YARA built-in ruleset deduplicates overlapping matches, so one `192.168.10.44`
yields one hit rather than one per start offset.

All scripts and the MCP server print `by QNX-Agent (Copyright Qi-NX)`.

## 0. Rules of engagement

- Default to read-only analysis. Only run an unknown sample inside a VM or sandbox isolated from production data.
- Record questions, hypotheses, and evidence in one running notes file (`<artifact>.notes.md`) as you go.
- Always compute and log SHA-256 of every input before analysis; reuse it as the canonical artifact id.

## 1. Triage

1. Identify container and architecture:
   - `file <bin>`, `xxd -l 64 <bin>`, `binwalk -E <bin>`, `diec <bin>` / `DetectItEasy`, `peid`, `osslsigncode verify`.
   - On Linux: `readelf -h`, `objdump -f`, `ldd`, `strings -a -n 6 -t x`.
   - On Windows PE: `pestudio`, `pe-sieve`, `dumpbin /headers /imports`.
2. Treat packing / encryption detection as a hypothesis:
   - High entropy + a small import table is a lead, not proof; compressed assets,
     encrypted resources, and stripped binaries can look the same.
   - Corroborate with section names, entry-point location, imports, YARA hits,
     and an independent tool such as DIE. State the evidence and confidence.
   - `no-known-packer-indicators` means only that these heuristics found nothing;
     it is not a clean-file verdict.
3. Extract quick IOCs:
   - URLs, IPs, mutexes, user-agents, file paths, registry keys.
   - `strings -a -n 6 -e l` for UTF-16LE; bulk extractor for bulk features.

## 2. Static analysis

- Disassemble:
  - IDA Pro / Ghidra / Binary Ninja for full PE/ELF/Mach-O; radare2 (`r2 -A`, `pdf`, `aaa`) for scripted work.
  - Always dump `.text` with `objdump -d -M intel` for cross-checks.
- When Ghidra is installed, use `mcp__uefi__ghidra_evidence` (or
  `python .dsh/skills/reverse-engineering/scripts/ghidra_evidence.py <binary> --json`)
  to export function prototypes, sizes, instruction counts, and call references
  with addresses and image-relative offsets. Treat these as Ghidra auto-analysis
  evidence; verify important paths in the disassembly and account for indirect
  calls or unresolved boundaries. This tool analyzes statically and does not run
  the sample.
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
- Do not launch a sample from the analyst host. Run it only in an explicitly
  isolated, disposable VM/sandbox with controlled networking. Export behavior
  telemetry, then normalize it with `mcp__uefi__dynamic_evidence` (or
  `dynamic_evidence.py`) for CAPE/Cuckoo JSON, Sysmon JSONL, and Procmon CSV.
  The returned timeline is capped at 2,000 events; split larger logs by time or
  process and correlate the separate outputs.
  Correlate each event with the artifact hash and static findings. The normalizer
  only reads existing exports; it does not execute samples or submit them to a
  remote service. Treat extracted domains/IPs as candidates until validated.

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

- When the user requests a report, produce a standalone, detailed report rather
  than a short summary. Use the user's language and this structure, adapting
  sections to the artifact while preserving the report header and declaration:

  ```markdown
  # Reverse-Engineering Analysis Report

  | Field | Value |
  |---|---|
  | Artifact / case | ... |
  | Report date | ... (include timezone when known) |
  | Analyst | QNX-Agent |
  | Scope | ... |
  | Status | Complete / Partial |

  ## 1. Executive Summary
  ## 2. Artifact Identification and Integrity
  ## 3. Scope, Environment, and Methodology
  ## 4. Triage Results
  ## 5. Detailed Findings
  ## 6. Capabilities and Behavior
  ## 7. Indicators of Compromise
  ## 8. MITRE ATT&CK Mapping (when applicable)
  ## 9. Detection and Mitigation Recommendations
  ## 10. Limitations and Unanswered Questions
  ## Appendix: Tool Results / Address and Offset Index (as useful)

  — QNX-Agent (Copyright Qi-NX)
  ```

- Include a table of contents for long reports. The artifact manifest must give
  filename, size, identified format, architecture, and available MD5/SHA-1/SHA-256
  hashes. Record the analysis date, scope, environment, and the tools actually
  used (including versions when available); distinguish planned from completed
  work.
- Make results complete and auditable: list every material finding and relevant
  negative result within the requested scope, and include supporting tables,
  addresses/offsets/RVAs, imports/strings/sections, IOC values, or call/data-flow
  evidence as applicable. Do not dump irrelevant raw output. If a value, check,
  or conclusion is unavailable, out of scope, or not tested, label it explicitly
  as `Not provided`, `Not available`, `Not tested`, or `Not confirmed`; never
  fabricate values or imply that an unrun check passed.
- For every claim, separate direct observation from interpretation and include
  evidence source (tool and output field or file location), confidence, plausible
  alternatives, and what further evidence would raise confidence. Never infer
  intent from a string or a single YARA hit alone. Treat packer, entropy, and
  YARA results as leads and corroborate them independently.
- Use clear table headers, stable finding IDs, severity and confidence where
  relevant. Include IOC tables, MITRE ATT&CK mapping, capability breakdown, and
  recommended detections (YARA, Sigma, Suricata) when applicable; state `None
  identified` only when the relevant checks were actually performed.
- Link every material claim to a stable evidence ID (`E-001`, `E-002`, ...), and
  every finding to one or more evidence IDs (`F-001` → `E-001`). The evidence
  ledger records the artifact SHA-256, tool/version, output field or method,
  address, file offset/image offset/RVA when applicable, and a concise direct
  observation. Keep evidence and interpretation in separate columns or bullets.
  Use [`templates/reverse-engineering-report.md`](../../../templates/reverse-engineering-report.md)
  when available; do not leave template placeholders in a delivered report.
- Before shipping a custom YARA rule, compile and backtest it with
  `mcp__uefi__yara_backtest` (or `yara_backtest.py`) against representative,
  hash-pinned positive and negative samples. Use the manifest's per-sample,
  per-rule boolean labels. Report TP/FP/FN/TN and precision/recall/F1 only for
  labeled pairs; unlabeled hits are not false positives. State corpus coverage
  and label limits, and revise rules with false positives or missed positives.
- End every report with the exact declaration `— QNX-Agent (Copyright Qi-NX)`
  on the final line, after all appendices and tables.

## 7.1 Adaptive workflow

- Start with `tool_status` and identify the container before selecting tools.
- PE/ELF/Mach-O: inspect metadata and imports; use YARA/strings for leads; choose
  disassembly only after a concrete function, capability, or protocol question is
  established.
- If packer signals agree, record each signal and confidence, then look for a
  safe unpacking route. If they disagree, keep the result as an unresolved lead.
- Script/archive/container: identify the format and extract a bounded layer at a
  time; re-hash each extracted artifact and repeat triage on it.
- Network capture/protocol: map framing and directions first, then test field
  hypotheses against multiple messages before writing a parser or claiming a
  protocol behavior.
- Stop when the requested question is answered with reproducible evidence; do
  not run every tool just because it is available.

## 7.2 Vulnerability scanning and security assessment

1. Define whether the scope is a source tree, dependency manifests, extracted
   filesystem, executable, or firmware image. Record the artifact/source revision
   and do not imply that a partial path represents the whole product.
2. Check `tool_status`, then choose `vulnerability_scan(scanner="osv")` for
   dependency advisories, `scanner="trivy"` for dependencies/misconfigurations/
   secrets, or `scanner="semgrep"` for source-code rules. Scanners may update
   databases or fetch remote rules; record the scanner version and scan time.
   The target is inspected, never launched.
3. Use `security_assessment` on saved Trivy, OSV-Scanner, Semgrep JSON, or SARIF
   to create stable finding/evidence IDs and severity counts. Secret values are
   redacted from normalized results.
4. Validate each material hit: exact component/version and affected range, fixed
   version, code reachability, configuration, exploit prerequisites, vendor
   backports, and compensating controls. Preserve advisory/rule ID, reference,
   file/line/offset, scanner/database version, confidence, and validation state.
   For compiled binaries without source, scanner coverage is limited; use Ghidra
   to trace externally controlled input through bounds checks, integer arithmetic,
   memory operations, authentication, and signature/crypto validation. A risky
   import or suspicious string alone is not a vulnerability.
5. Separate confirmed vulnerabilities from likely issues, scanner-only leads,
   and untested areas. Explain impact, exposure, severity rationale, fixes, and
   residual risk. A no-findings result is limited to the recorded scanner,
   rules/database, target, and coverage; it is not proof of security.

## 8. Subagent fan-out pattern

For work items longer than ~5 static passes or with independent threads (e.g. one thread unpacks while another parses a C2 protocol), dispatch a `subagent` per thread with a tightly-scoped brief. The parent keeps the running notes file and synthesises findings; children return string/IOC tables and address maps.

## 9. Tool-friendly formats

- Dumps: produce `.id0/.id1`, `.gpr`, `.i64` where applicable; otherwise export `objdump` listings and radare2 projects.
- Patch: emit unified diff against the original bytes; include both offset and RVA.
- Pseudocode: C99 with explicit widths (`uint32_t`); name locals after observations, not generically.
