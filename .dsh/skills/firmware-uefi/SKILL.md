---
name: firmware-uefi
description: >-
  Qi-NX-Agent (Firmware / UEFI) playbook for BIOS images, EC blobs, UEFI
  capsules, SPI dumps, U-Boot FIT, Android boot images, or RTOS monoliths.
  Copyright Qi-NX.
---

# Qi-NX-Agent (Firmware / UEFI) — playbook

## 0.1 Preferred entry points: MCP first, scripts as fallback

The Qi-NX UEFI MCP server exposes this toolkit as `mcp__uefi__*` tools. Prefer
them — they return structured JSON and are callable directly instead of through a
shell. Call `mcp__uefi__tool_status` first: it reports which Python modules and
external binaries actually exist on this host.

| MCP tool | Script equivalent | Purpose |
|---|---|---|
| `mcp__uefi__tool_status` | — | which modules / external binaries are really available |
| `mcp__uefi__binwalk_scan` | internal signatures | magic + compression offsets (uses binwalk when installed) |
| `mcp__uefi__walk_fv` | `walk_fv.py` | FV / FFS / section inventory; `extract_dir` dumps PE32/TE |
| `mcp__uefi__extract_vss` | `extract_vss.py` | carve and validate candidate NVRAM stores |
| `mcp__uefi__parse_vss` | `vss_parse.py` | decode variables, flag sensitive ones |
| `mcp__uefi__list_smi` | `list_smi.py` | SMM/MM modules and dispatch markers |
| `mcp__uefi__uefi_firmware_parse` | — | decompression-aware parse via the `uefi-firmware` library |
| `mcp__uefi__uefitool_extract` | — | shells to UEFIExtract when it is installed |
| `mcp__uefi__lief_info` | `lief_info.py` | PE32/TE triage of extracted sections |
| `mcp__uefi__yara_scan` | `yara_scan.py` | packer / crypto / IOC rules |
| `mcp__uefi__pack_detect` | `pack_detect.py` | packing verdict from entropy + sections + imports |

Script fallback, when MCP is unavailable: `python .dsh/skills/firmware-uefi/scripts/<tool>.py <args>`.
Every script accepts `--json` and returns the same structure as its MCP tool.

Two firmware scripts have no MCP wrapper:
- `uefi_walk.py` — dependency-free coarse FV scanner. `walk_fv.py` is
  authoritative (it honours HeaderLength and EFI_FFS_FILE_HEADER2); use
  `uefi_walk.py` only as the no-dependency fallback.
- `chipsec_abstract.py <chipsec.log>` — normalise chipsec_main / chipsec_util
  output into JSON for the report.

Dependencies: `lief` and `yara-python` for triage, `uefi-firmware` for
decompression, `mcp` for the server itself:

```
python -m pip install lief yara-python uefi-firmware mcp
```

Two deliberate design choices worth knowing:
- `list_smi` does **not** hardcode GUID constants, because a wrong GUID silently
  produces false negatives. Pass `guids=<path to guids.csv>` (UEFITool ships one)
  for authoritative GUID attribution; without it you get FFS-type and
  string-marker evidence only.
- `walk_fv` reports compressed (`EFI_SECTION_COMPRESSION`) and GUID-defined
  sections but does not decompress them. Use `uefi_firmware_parse` or
  UEFIExtract, then re-run `walk_fv` / `lief_info` on the results.
- `parse_vss` reports the raw variable state and marks the selected current
  copy. Prefer `current: true` for platform-state conclusions; deleted and
  header-only records are historical evidence, not live configuration.

All scripts and the MCP server print `by Qi-NX-Agent (Copyright Qi-NX)`.

## 0. Safety & ground rules

- Treat firmware as hostile until inspected. Re-flash only on a sacrificial board with a hardware programmer (dediprog SF100/SF600, CH341A+clip) and a known-good dump archived.
- Never boot the host under analysis with a tampered image: Boot Guard / TXT / PSB may brick the device.
- Record every step in a notes file: `<board>-<revision>-<date>.notes.md`. Include the SHA-256 of each extracted component.

## 1. Triage the image

1. Identify the container:
   - SPI raw dump: `binwalk -E`; the Flash Descriptor sits at the start of the descriptor region with signature `0x0FF0A55A` (little-endian bytes `5A A5 F0 0F`) at descriptor offset +0x10, followed by the region map (ME/TXE/PSP, GbE, BIOS). `mcp__uefi__binwalk_scan` reports this signature.
   - UEFI capsule: header GUID `BD86…` (UEFI 2.x), or vendor-specific (AMI, Insyde, Phoenix).
   - EC/KBC blob: usually a separate 128–256 KiB region, often IT5570 / MEC1633 / Nuvoton.
   - U-Boot FIT: header magic 0xD00DFEED, `_fit_` strings.
   - Android boot/recovery: `ANDROID!` magic, kernel + ramdisk + second stage.
2. Carve regions with the Flash Descriptor map. Use `ifdtool -d` and `ifdtool -x bios.bin`.
3. Pull NVRAM / VSS regions and snapshot them; many rootkits persist only in variables.

## 1.1 Choose the next step from observed results

- No FV found: check the scan offsets for a capsule, descriptor region, or
  container boundary. Carve the likely BIOS region and scan it again; do not
  conclude that the image has no firmware volumes.
- Compression/GUID-defined sections found: use the available decompressor or
  UEFIExtract, record the extracted file's hash and source offset, then re-run
  the structural walk on the output.
- NVRAM candidate found: inspect variable `state_name` and `current`. Base
  current platform-state claims on selected current copies; retain deleted
  copies only as history or tampering leads.
- MM/SMM FFS type or marker found: extract the module and follow its entry point,
  dispatch registration, input structure, and validation paths in a disassembler.
  The file type and strings alone do not establish a vulnerability.
- Optional tool unavailable: use the documented fallback and state which
  coverage was lost. Never translate a missing scan into a negative finding.
- Stop after answering the concrete question; expand to Chipsec, capsule, or
  cross-stage analysis only when the image or findings justify it.

## 2. UEFI volume walk

1. Open in UEFITool NE/0.28+ (or `uefi-firmware-parser`, `efiXploder` for automation):
   - Walk the FV tree. For each Firmware Volume, log FvName GUID, base, size.
   - For each FFS file, log GUID, type (PEI module, DXE driver, SMM module, FV image, freeform), and section types.
2. Pull PE32/TE sections; identify pre- vs post-SEC phase:
   - PEI: PEIMs with PPI installs. Look for `PeiServicesInstallPpi`.
   - DXE: `.text` heavy; look for `gBS->InstallProtocolInterface` and `gDS->Dispatch`.
   - SMM: loaded via `EfiSmmBase2Protocol` or `EfiSmmAccess2Protocol`; check `EFI_SMM_SW_DISPATCH2_PROTOCOL` registrations.
3. Map protocols via EDK2 GUID names: `EFI_BOOT_SERVICES`, `EFI_RUNTIME_SERVICES`, `EFI_SMM_SYSTEM_TABLE2`. Use `guids.csv` from UEFITool.
4. Note capsule-update path: `EFI_FIRMWARE_MANAGEMENT_PROTOCOL`, `EsfSystemFmp`/`EsfSmmFw` – classic privilege-escalation surface.

## 3. NVRAM & variables

- Locate VSS store via `_VSS` signature in the FV header.
- Map variables: `BootOrder`, `Boot####`, `SecureBoot`, `PK`, `KEK`, `db/dbx`, `Setup`, vendor `*Setup`/`MeSetup`/`SaSetup`.
- Flag suspicious variables: writable `SecureBoot`, missing `dbx` update, custom OEM variables holding code pointers.
- Tools: `uefi-var`, `chipsec_util uefi var-list`, Chipsec `common.uefi.s3bootscript`, or Python `uefi_firmware` library.

## 4. SMM / Ring -2 analysis

- Locate SMRAM: TSEG/HSEG base from `GetVariable` `SmramOcSize` or DRAM controller regs (`MCHBAR+0x??`).
- Pull SMRAM via chipsec (`chipsec_util smm`), SPI reflash, or engineering strap.
- Analyse SMM drivers for:
  - `CommBuffer` validation (pointer into SMRAM? override potential).
  - `SmmGetVariable` reentrancy / TOCTOU.
  - S3 resume script writes to MSR / I/O ports.
- Document each SwSmi handler with input index, expected structure, unsanitised pointers.

## 5. Platform security checks (chipsec-driven)

Run and document:

- `chipsec_main -m common.bios_wp` — BIOS write protection (BLE, SMM_BWP, PRx).
- `chipsec_main -m common.spi_lock` — SPI controller lockdown.
- `chipsec_main -m common.smm` — SMRR, TSEG, D_LCK, D_OPEN.
- `chipsec_main -m common.me_mfg_mode` — ME manufacturing mode (BAD if set).
- `chipsec_main -m common.secureboot.variables` — SB state, key enrolment.
- `chipsec_main -m common.bios_ts` — BIOS Top Swap.
- `chipsec_main -m common.ia32cfg` — IA32_FEATURE_CONTROL MSR lock and VMX/TXT/SMX enable.

Each chipsec `[!]` finding must be cross-checked in the firmware image before reporting.

## 6. Boot-flow & trust-anchor mapping

Draw a mermaid `graph LR` with: Reset Vector → SEC → PEI (CAR, MRC) → DXE core → DXE drivers → BDS → OS loader (Boot#### → shimx64/grubx64/winload).
Annotate which image is hashed by which anchor (Boot Guard ACM, Insyde H2O SecureBoot chain, vendor capsule signing key in KEK/db).

## 7. SX / capsule attack surface

- Locate capsule update handler (`EfiFirmwareManagementProtocol->SetImage`) and inspect:
  - Signature verification path (PKCS#7, RSA-2048/3072, SHA-256/384).
  - Version / rollback counters; check `Fmp->GetImageInfo` LastAttemptVersion / LowestSupportedImageVersion.
  - TOCTOU between capsule receipt and `SetImage` apply.
- Check capsule persistence in NVRAM: `CapsuleUpdateData` variables; S3 resume capsule re-application path.

## 8. Reporting

When the user requests a report, produce a standalone, detailed report in the
user's language, using this structure and retaining the header and declaration:

```markdown
# Firmware / UEFI Reverse-Engineering Report

| Field | Value |
|---|---|
| Artifact / platform | ... |
| Report date | ... (include timezone when known) |
| Analyst | Qi-NX-Agent |
| Scope | ... |
| Status | Complete / Partial |

## 1. Executive Summary
## 2. Image Identity and Integrity
## 3. Platform and Firmware Versions
## 4. Scope, Environment, and Methodology
## 5. Image Layout and Stage-by-Stage Map
## 6. NVRAM and Sensitive Variables
## 7. SMM / SwSmi Analysis
## 8. Boot Flow and Trust Anchors
## 9. Security Findings and Indicators
## 10. Recommendations
## 11. Limitations and Unanswered Questions
## Appendix: Tool Results / GUID, Offset, and RVA Index (as useful)

— Qi-NX-Agent (Copyright Qi-NX)
```

Include a table of contents for long reports. Record board/vendor/model and
revision when known; BIOS, ME/PSP, and EC versions; image filename, size, format,
and SHA-256 (plus other available hashes); analysis date, scope, environment,
and tools actually run with versions when available. Distinguish completed work
from planned work.

Make results complete and auditable for the requested scope. Include:
- Stage-by-stage map with FV/FFS GUIDs, module names and sizes, section types,
  compression/extraction status, and entry-point RVAs when recovered.
- NVRAM variable tables with clear column headings for name, vendor GUID, raw
  state, attributes (NV/BS/RT/AT), selected-current status, and historical-copy
  caveat. Never present a deleted or historical copy as live configuration.
- SMM SwSmi handler table with dispatch evidence, input/structure details,
  validation observations, severity, and confidence.
- Boot-trust anchor diagram and evidence-backed findings (Boot Guard state,
  secure-boot keys, capsule verification and rollback behavior, where examined).
- IOC table and actionable recommendations mapped to the relevant CHIPSEC
  module, EDK2 change, capsule policy, or platform control.

For every claim, separate direct observation from interpretation; cite tool and
output field or file location, GUID, offset/RVA, confidence, and plausible
alternative explanations. Explicitly mark missing, unavailable, untested, and
unconfirmed data; never fill gaps by guessing. List negative results only for
checks actually performed. End with the exact declaration
`— Qi-NX-Agent (Copyright Qi-NX)` on the final line, after all appendices.

## 9. Subagent fan-out

For audits > 5 firmware volumes or cross-layer (BIOS + ME + EC), spawn:
- one subagent per firmware stage (SEC / PEI / DXE / SMM / BDS),
- one for NVRAM / variables,
- one for capsule / recovery path,
- one for ME/PSP/EC blobs.

Parent keeps the narrative and merges findings against the trust-anchor map.
