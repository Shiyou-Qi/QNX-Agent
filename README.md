<div align="center">

# Qi-NX-Agent

### Reverse-engineering, firmware forensics, and protocol analysis for DeepSeek Harness.

**Three focused agents. One local MCP toolkit. Evidence-first analysis from triage to report.**

[![GitHub stars](https://img.shields.io/github/stars/Shiyou-Qi/Qi-NX-Agent?style=for-the-badge&logo=github&color=171717)](https://github.com/Shiyou-Qi/Qi-NX-Agent/stargazers)
[![Last commit](https://img.shields.io/github/last-commit/Shiyou-Qi/Qi-NX-Agent?style=for-the-badge&logo=git&color=7c3aed)](https://github.com/Shiyou-Qi/Qi-NX-Agent/commits/main)
[![DeepSeek Harness](https://img.shields.io/badge/DeepSeek%20Harness-Agent%20Presets-0ea5e9?style=for-the-badge)](https://github.com/Shiyou-Qi/Qi-NX-Agent)
[![Python](https://img.shields.io/badge/Python-3.x-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)

<br />

**By Qi-NX-Agent · Copyright Qi-NX**

</div>

---

> **A reverse-engineering workbench for DSH.** Choose a specialist persona, inspect binaries or firmware with structured tools, and turn evidence into a traceable report. The toolkit favors reproducible results, explicit uncertainty, and safe handling of hostile samples.

## At a glance

| | Included |
|---|---|
| **Agent presets** | Binary / protocol, Firmware / UEFI, and a coordinating Team Lead |
| **MCP server** | Local `mcp__uefi__*` tools for triage, firmware parsing, and NVRAM analysis |
| **Analysis scripts** | Nine standalone Python utilities; JSON output supported |
| **Install model** | One composition bundle for the complete kit, or individual bundles for development |
| **Reporting** | Structured reports with artifact identity, evidence, confidence, limitations, and a signed footer |

## Choose your specialist

Install the complete bundle once, then select the preset that fits the task in the DSH Agent selector.

| Preset | Best for | Focus |
|---|---|---|
| **Qi-NX-Agent** (`reversing`) | Unknown binaries and protocol behavior | PE / ELF / Mach-O triage, packing leads, imports, strings, crypto, obfuscation, and protocol reversing |
| **Qi-NX-Agent (Firmware / UEFI)** (`uefi`) | BIOS images, SPI dumps, and capsules | FV / FFS structure, NVRAM / VSS, SMM triage, boot flow, and trust anchors |
| **Qi-NX-Agent (Team Lead)** (`reversing-team`) | Multi-layer investigations | Coordinates binary and firmware work, delegates scoped threads, and synthesizes findings |

Each preset loads its matching playbook:

- [Binary and protocol reverse-engineering playbook](.dsh/skills/reverse-engineering/SKILL.md)
- [Firmware and UEFI playbook](.dsh/skills/firmware-uefi/SKILL.md)

## What makes the workflow useful

### Evidence before conclusions

The agent identifies the artifact and architecture before deeper analysis, selects follow-up tools from observed evidence, and treats packer, entropy, and YARA results as leads that need corroboration. Findings distinguish direct observations from interpretation and cite hashes, tool output, GUIDs, offsets, or RVAs where available.

### Detailed reports, not just a verdict

Requested reports use a clear title and metadata header, an executive summary, artifact identity and hashes, scope and methodology, detailed evidence-backed findings, relevant IOC and mapping tables, recommendations, limitations, and useful appendices. Unknown, unavailable, and untested information is labeled instead of guessed. Reports end with:

```text
— Qi-NX-Agent (Copyright Qi-NX)
```

### Local tools, structured results

The [UEFI MCP server](dsh-uefi-mcp/) exposes the toolkit as local `mcp__uefi__*` tools over stdio. Use them from a preset or run the Python scripts directly; scripts support `--json` for automation.

## Toolkit

| Tool | What it does |
|---|---|
| [`walk_fv.py`](.dsh/skills/firmware-uefi/scripts/walk_fv.py) | Walk firmware volumes, FFS files, and sections; optionally extract PE32 / TE sections |
| [`extract_vss.py`](.dsh/skills/firmware-uefi/scripts/extract_vss.py) | Locate, validate, and carve candidate UEFI variable stores |
| [`vss_parse.py`](.dsh/skills/firmware-uefi/scripts/vss_parse.py) | Decode variables and identify Secure Boot-related records and state |
| [`list_smi.py`](.dsh/skills/firmware-uefi/scripts/list_smi.py) | Enumerate SMM modules and dispatch markers for follow-up analysis |
| [`uefi_walk.py`](.dsh/skills/firmware-uefi/scripts/uefi_walk.py) | Dependency-light fallback firmware-volume scanner |
| [`chipsec_abstract.py`](.dsh/skills/firmware-uefi/scripts/chipsec_abstract.py) | Normalize CHIPSEC logs into structured JSON |
| [`lief_info.py`](.dsh/skills/reverse-engineering/scripts/lief_info.py) | Identify PE / ELF / Mach-O metadata, sections, imports, and exports |
| [`pack_detect.py`](.dsh/skills/reverse-engineering/scripts/pack_detect.py) | Assess packer / protector indicators using multiple heuristics |
| [`yara_scan.py`](.dsh/skills/reverse-engineering/scripts/yara_scan.py) | Scan built-in triage rules or a supplied YARA ruleset |

The MCP server also provides availability checks, binary triage, signature scans, firmware parsing, and extraction helpers. See the [MCP server guide](dsh-uefi-mcp/README.md) for the complete tool list and protocol details.

## Install

### Option A — Install the complete kit (recommended)

In the DSH plugin manager, install the GitHub bundle:

```text
plugin_manager  action=install_bundle  target=github:Shiyou-Qi/Qi-NX-Agent
```

The root `package.json` composes the three presets and the MCP bundle into one install target.

### Option B — Install one bundle while developing

```text
plugin_manager  action=install_bundle  target=<absolute path to a bundle directory>
```

Available bundle directories: `dsh-reversing-preset`, `dsh-uefi-preset`, `dsh-reversing-team-preset`, and `dsh-uefi-mcp`.

> **Choose one install mode.** The root bundle and standalone bundles declare the same row IDs. Installing both can create duplicate declarations.

After installation, choose an Agent preset in the DSH GUI. If you change files in an already installed local bundle, disable and re-enable it to reload the patch:

```text
plugin_manager  action=set_bundle  target=@local/dsh-uefi-preset  enabled=false
plugin_manager  action=set_bundle  target=@local/dsh-uefi-preset  enabled=true
```

If the plugin manager reports `ambiguous-install`, the bundle is already installed; toggle or remove the existing installation instead of adding a duplicate. A live session may keep tools in use, so restart DSH before removing a bundle that reports `bundle-in-use`.

## Dependencies

Install Python packages into the interpreter used by DSH to run commands:

```powershell
& "<DSH python>" -m pip install lief yara-python uefi-firmware mcp
```

| Package | Used by | If missing |
|---|---|---|
| `lief` | `lief_info`, `pack_detect` | Tools return a structured missing-dependency error |
| `yara-python` | `yara_scan` | Scanner returns a structured missing-dependency error |
| `uefi-firmware` | Decompression-aware firmware parsing; optional `uefi_walk` path | Firmware MCP parser reports the limitation and suggests `walk_fv`; fallback scanner remains available |
| `mcp` | MCP server | Server reports the startup failure on stderr |

Core firmware parsers `walk_fv`, `extract_vss`, `vss_parse`, `list_smi`, and `chipsec_abstract` use the Python standard library. `uefi_walk` also works without optional dependencies.

### Optional external tools

| Tool | Purpose | Notes |
|---|---|---|
| **binwalk** | Extended signatures and embedded-data triage | The scanner has an internal signature fallback; Windows users can use WSL or a Rust build |
| **UEFIExtract** | Extract compressed or GUID-defined sections | Available from [LongSoft / UEFITool](https://github.com/LongSoft/UEFITool); add `UEFIExtract` to `PATH` |
| **CHIPSEC** | Live platform security checks and logs | Run checks on the target system; `chipsec_abstract` only parses logs and does not require CHIPSEC |

The built-in binwalk fallback recognizes 23 signatures, including firmware volumes, flash descriptors, common compression formats, Android boot images, FIT / DTB, PE / ELF, and selected firmware compression GUIDs. Results identify which scanner produced them.

## Verify the checkout

Run the bundled verification suite with the same Python interpreter DSH uses:

```powershell
& "<DSH python>" tests/verify_all.py
```

The suite compiles scripts, checks their help output, validates parsers against generated firmware fixtures, exercises LIEF / YARA against a real binary, and checks MCP JSON-RPC behavior over stdio.

## Repository map

```text
.
├── package.json                    Complete composition bundle
├── dsh-reversing-preset/           Binary / protocol preset
├── dsh-uefi-preset/                Firmware / UEFI preset
├── dsh-reversing-team-preset/      Coordinating Team Lead preset
├── dsh-uefi-mcp/                   Local MCP server and bundle
├── .dsh/skills/                    Playbooks and Python utilities
└── tests/                          Fixtures and verification suite
```

## Scope and limitations

- **Heuristics are not verdicts.** A packer or YARA hit is a lead; no known indicator does not establish that a file is clean.
- **Firmware extraction has boundaries.** `walk_fv` identifies compressed and GUID-defined sections but does not decompress them; use `uefi_firmware_parse` or UEFIExtract, then triage extracted content again.
- **Some attribution needs reference data.** `list_smi` does not hardcode protocol GUIDs. Supply an authoritative `guids.csv` for GUID attribution; otherwise findings are based on structural and string-marker evidence.
- **NVRAM can contain historical records.** `vss_parse` marks the selected current copy. Deleted records can be useful forensic evidence, but are not live configuration.
- **SMM inventory is not handler recovery.** `list_smi` finds modules and dispatch markers; use a disassembler to recover handler inputs and validate behavior.
- **Hostile artifacts require isolation.** Do not execute malware-class samples on the host. Use a sandbox or VM; firmware flashing belongs on a sacrificial, recoverable target.

## Troubleshooting preset activation

If presets stop loading, inspect `$DSH_HOME/profiles/<profile>/cordis.yml`. The profile root should remain an empty entry list (`[]`); bundle patches build the tree. A populated profile root can duplicate inserted rows and cause activation failures. Restore the empty list and let the bundle patches rebuild the profile.

---

<div align="center">

**Qi-NX-Agent · Copyright Qi-NX**<br />
Built for careful analysis. Ground conclusions in evidence.

</div>
