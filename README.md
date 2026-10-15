# Qi-NX — reverse-engineering agents for DeepSeek Harness

A reverse-engineering toolkit for DSH: three selectable Agent presets, an MCP
server exposing the analysis tools, and a dependency-light Python toolkit for
binaries and firmware.

**by Qi-NX-Agent, Copyright Qi-NX.**

---

## What you get

### Three Agent presets

Pick one per session from the Agent-preset selector in the DSH GUI.

| Preset | Name shown | Focus |
|---|---|---|
| `reversing` | Qi-NX-Agent | binaries, packing, protocol reversing, crypto/obfuscation |
| `uefi` | Qi-NX-Agent (Firmware / UEFI) | SPI dumps, UEFI capsules, FV/FFS, NVRAM, SMM, boot trust anchors |
| `reversing-team` | Qi-NX-Agent (Team Lead) | both disciplines, driven as a lead that fans work out to specialists |

Each preset loads its matching skill playbook:

- [`.dsh/skills/reverse-engineering/SKILL.md`](.dsh/skills/reverse-engineering/SKILL.md)
- [`.dsh/skills/firmware-uefi/SKILL.md`](.dsh/skills/firmware-uefi/SKILL.md)

### MCP server: `mcp__uefi__*`

[dsh-uefi-mcp/](dsh-uefi-mcp/) runs a local MCP server over stdio. Eleven tools
are callable directly by any preset — see [its README](dsh-uefi-mcp/README.md).

### Python toolkit

Nine scripts, all usable standalone (`--json` supported) or through MCP.

| Script | Purpose |
|---|---|
| [`walk_fv.py`](.dsh/skills/firmware-uefi/scripts/walk_fv.py) | authoritative FV / FFS / section walk; `--extract` dumps PE32 and TE sections |
| [`extract_vss.py`](.dsh/skills/firmware-uefi/scripts/extract_vss.py) | locate, validate and carve UEFI NVRAM variable stores |
| [`vss_parse.py`](.dsh/skills/firmware-uefi/scripts/vss_parse.py) | decode variables; flag SecureBoot / PK / KEK / db / dbx / Setup |
| [`list_smi.py`](.dsh/skills/firmware-uefi/scripts/list_smi.py) | enumerate SMM (Ring -2) modules and their dispatch markers |
| [`uefi_walk.py`](.dsh/skills/firmware-uefi/scripts/uefi_walk.py) | coarse, dependency-free FV scanner (fallback for `walk_fv`) |
| [`chipsec_abstract.py`](.dsh/skills/firmware-uefi/scripts/chipsec_abstract.py) | normalise `chipsec_main` / `chipsec_util` logs into JSON |
| [`lief_info.py`](.dsh/skills/reverse-engineering/scripts/lief_info.py) | PE / ELF / Mach-O triage: format, arch, sections, imports, exports |
| [`pack_detect.py`](.dsh/skills/reverse-engineering/scripts/pack_detect.py) | packer / protector verdict from entropy, section names, import shape |
| [`yara_scan.py`](.dsh/skills/reverse-engineering/scripts/yara_scan.py) | built-in triage ruleset (packers, crypto constants, IOCs) or your own rules |

---

## Layout

```
.
├── README.md                      this file
├── package.json                   the whole kit as ONE installable bundle
├── dsh-reversing-preset/          preset `reversing`      (also a standalone bundle)
├── dsh-uefi-preset/               preset `uefi`           (also a standalone bundle)
├── dsh-reversing-team-preset/     preset `reversing-team` (also a standalone bundle)
├── dsh-uefi-mcp/                  MCP server + its bundle patch
├── tests/                         reproducible verification
└── .dsh/skills/
    ├── reverse-engineering/       SKILL.md + scripts/
    └── firmware-uefi/             SKILL.md + scripts/
```

The root `package.json` is a **composition bundle**: its `dsh.bundle.patch` is an
array pointing at the four sub-patches, so installing the repository once
registers all four rows with no duplicated content. That's what makes
`github:<owner>/Qi-NX-Agent` a valid install target.

Each subdirectory is also a standard DSH bundle on its own: a `package.json`
declaring `dsh.bundle.patch`, and a `cordis.patch.yml` inserting its rows.

---

## Install

**Pick one of the two modes — do not install both.** The root bundle and the
four sub-bundles declare the *same* row ids (`preset-reversing`, `preset-uefi`,
`preset-reversing-team`, `uefi-mcp`); installing both leaves duplicate
declarations for the same rows.

### Mode A — the whole kit, from the repository

```
plugin_manager  action=install_bundle  target=github:Shiyou-Qi/Qi-NX-Agent
```

One package, four rows. This is the mode a cloner gets.

### Mode B — individual bundles, by directory path

```
plugin_manager  action=install_bundle  target=<absolute path to a bundle dir>
```

Better while developing one bundle: you can toggle it alone without reloading
the others.

Then select the preset per session in the GUI. To remove:

```
plugin_manager  action=remove_bundle  target=@local/dsh-uefi-preset
```

After editing a bundle's files, a plain re-install reports `ambiguous-install`
because the bundle is already present. Toggle it instead:

```
plugin_manager  action=set_bundle  target=@local/dsh-uefi-preset  enabled=false
plugin_manager  action=set_bundle  target=@local/dsh-uefi-preset  enabled=true
```

`remove_bundle` can report `bundle-in-use` while a live session is using the
bundle's rows — for example while `mcp__uefi__*` tools are callable. Remove it
after a restart, or disable it first.

---

## Dependencies

### Python packages

Install into the interpreter DSH spawns commands with:

```powershell
& "<DSH python>" -m pip install lief yara-python uefi-firmware mcp
```

| Package | Needed by | Without it |
|---|---|---|
| `lief` | `lief_info`, `pack_detect` | both return a structured error naming the missing package |
| `yara-python` | `yara_scan` | same |
| `uefi-firmware` | the `uefi_firmware_parse` MCP tool, and `uefi_walk`'s optional structured path | `uefi_firmware_parse` returns a structured error and names `walk_fv` as the fallback; `uefi_walk` silently uses its own coarse scanner |
| `mcp` | the MCP server itself | the server refuses to start and says so on stderr |

`walk_fv`, `extract_vss`, `vss_parse`, `list_smi` and `chipsec_abstract` are
pure standard library. `uefi_walk` is too, except that it opportunistically uses
`uefi-firmware` when present — the import sits inside a `try/except`, so it runs
either way. Nothing in the firmware toolkit requires a package to be installed.

### External tools (optional)

These are genuinely absent on many hosts. Every tool that wants one reports its
absence explicitly instead of failing silently.

| Tool | Used by | Get it |
|---|---|---|
| **binwalk** | `binwalk_scan` | v2: `pip install binwalk`. v3 is a Rust rewrite: `cargo install binwalk`. Linux: `apt install binwalk`. On Windows, prefer WSL or the Rust build. |
| **UEFIExtract** | `uefitool_extract` | Download a release from [LongSoft/UEFITool](https://github.com/LongSoft/UEFITool) and put `UEFIExtract` on `PATH`. Needed only to decompress compressed/GUID-defined sections. |
| **chipsec** | produces the logs that `chipsec_abstract` parses (parsing itself needs nothing) | `pip install chipsec`. Live platform checks require kernel-driver access, so run chipsec on the machine under test and feed its log to `chipsec_abstract`. |

`binwalk_scan` degrades to a built-in 23-signature scanner (UEFI FV, flash
descriptor, `$FPT`, gzip/xz/bzip2/zstd/lz4/lzma, squashfs, cramfs, UBI, JFFS2,
Android boot, FIT/DTB, ELF/PE, Tiano and LZMA decompression GUIDs) and labels the
result `internal-signature-scan` so you always know which scanner answered.

---

## Verification

Everything is checkable from one command:

```powershell
& "<DSH python>" tests/verify_all.py
```

It compiles every script, runs `--help` on each, builds a **hand-made UEFI image**
with known-good values, asserts the parsers reproduce those exact offsets, sizes,
GUIDs, attributes and marker sets, checks the extract→parse chain equals
parse-in-place, exercises the LIEF/YARA tools against a real binary, and runs MCP
protocol conformance over stdio.

The suite has been extended with nested-FV and variable-state cases. Re-run it
after local changes to confirm the current checkout.

`tests/` contents:

- [`fixtures.py`](tests/fixtures.py) — the fixture generator and its expectations
- [`test_mcp_protocol.py`](tests/test_mcp_protocol.py) — raw JSON-RPC conformance test
- [`test_edge_cases.py`](tests/test_edge_cases.py) — nested FV and variable-state cases
- [`verify_all.py`](tests/verify_all.py) — the orchestrator
- `tests/artifacts/` — regenerated on every run

The MCP test speaks newline-delimited JSON-RPC directly rather than using a
client SDK, so it cannot pass by accidentally testing a different client
version than DSH uses.

---

## Design decisions and honest limitations

- **No hardcoded GUID constants.** `list_smi` does not embed protocol GUIDs: a
  wrong GUID yields silent false negatives, which is worse than no check. Pass
  `guids=<path to guids.csv>` (UEFITool ships one) for authoritative GUID
  attribution. Without it you get FFS-type and string-marker evidence.
- **`walk_fv` does not decompress.** It parses and reports
  `EFI_SECTION_COMPRESSION` and `EFI_SECTION_GUID_DEFINED` sections, including
  the compression kind and uncompressed size, but leaves them packed. Use
  `uefi_firmware_parse` or UEFIExtract, then re-run `walk_fv` / `lief_info`.
- **Variable-store detection is heuristic.** `extract_vss` probes the plausible
  store-header prefix lengths (0x20, 0x1C, 0x18, 0x10, 0x00) because real images
  vary, validates each candidate by walking its `0x55AA` variable headers, and
  records `reason` / `confidence` / `variables_validated` on every candidate so
  you can judge it rather than trust it.
- **`list_smi` is a triage enumerator, not a disassembler.** It does not recover
  SwSmi handler input values. Use its module list with IDA/Ghidra and
  `gEfiSmmSwDispatch2ProtocolGuid` cross-references for the handler table.
- **NVRAM records can be historical.** `parse_vss` reports each raw EDK II
  variable state and marks the selected current copy. Deleted records may still
  be useful forensic evidence, but should not be treated as live configuration.
- **Packer verdicts are leads.** `pack_detect` includes the signals that drove
  its verdict; `no-known-packer-indicators` does not mean the file is clean.
- **The MCP protocol negotiates down to 2025-11-25.** The Python SDK's latest
  revision is 2026-07-28 but its server side currently answers 2025-11-25; the
  DSH client documents exactly this fallback, and the tools register correctly.
- **Firmware and malware are treated as hostile.** The preset personas require a
  re-flashable board or a VM/sandbox for any execution, and never let analysed
  Ring -2 or malware-class code run on the host.

---

## Team tools

`reversing-team` always provides `subagent`, `subagent_fork` and `workflow`. The
Agent Teams tools (`spawnTeammate`, the task board, `sendMessage`,
`waitForChange`) come from the experimental bundle, which publishes `agent-team`
and `tool-agent-team` on the **Host plane**:

```
plugin_manager  action=set_bundle  target=@deepseek-ai/dsh-experimental-agent-team-profile  enabled=true
```

Presets do not — and must not — declare those row ids themselves. Two rules
govern this, both learned the hard way:

- **A preset must not declare a row id the Host plane already provides.** The
  preset-plane gate resolves row ids across planes, so a duplicate declaration
  breaks the preset's activation even when the preset's copy is `disabled`.
- **A preset must not declare a row id whose module may be absent.** With the
  team bundle disabled, `@deepseek-ai/dsh-experimental-tool-agent-team` is not
  installed at all, so a declared row cannot resolve.

An earlier revision of `reversing-team` gated its `tool-agent-team` row with
`disabled: !!js "!ctx.get('agentTeams')"`. That fails in *both* configurations —
which is why the row is gone. Host-plane tools are visible to every preset
automatically, so nothing is lost.

Be aware that enabling the bundle is a profile-wide live change: it overrides the
`tool-subagent*` rows for **every** session. Reversible with `enabled=false`.

### A note on profile breakage

If presets stop loading, check `$DSH_HOME/profiles/<profile>/cordis.yml`. It is
the profile root and must stay an **empty entry list** (`[]`); the tree is built
by the bundle patches. If it has been rewritten as a full entry list, the
bundles' `insert:` rows are declared twice and row addressing degrades — presets
show as failing with no `patchId`. Restoring it to `[]` rebuilds the tree from
the patches.

---

*by Qi-NX-Agent, Copyright Qi-NX.*
