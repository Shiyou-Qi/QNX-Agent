<div align="center">

# QNX-Agent

### Reverse-engineering, Android APK security, firmware forensics, and protocol analysis for DeepSeek Harness.

**Four selectable presets. One local MCP toolkit. Evidence-first analysis from triage to report.**

[![GitHub stars](https://img.shields.io/github/stars/Shiyou-Qi/Qi-NX-Agent?style=for-the-badge&logo=github&color=171717)](https://github.com/Shiyou-Qi/Qi-NX-Agent/stargazers)
[![Last commit](https://img.shields.io/github/last-commit/Shiyou-Qi/Qi-NX-Agent?style=for-the-badge&logo=git&color=7c3aed)](https://github.com/Shiyou-Qi/Qi-NX-Agent/commits/main)
[![DeepSeek Harness](https://img.shields.io/badge/DeepSeek%20Harness-Agent%20Presets-0ea5e9?style=for-the-badge)](https://github.com/Shiyou-Qi/Qi-NX-Agent)
[![Python](https://img.shields.io/badge/Python-3.x-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)

<br />

**By QNX-Agent · Copyright Qi-NX**

</div>

---

> **A reverse-engineering workbench for DSH.** Choose a specialist persona, inspect binaries or firmware with structured tools, and turn evidence into a traceable report. The toolkit favors reproducible results, explicit uncertainty, and safe handling of hostile samples.

## At a glance

| | Included |
|---|---|
| **Agent presets** | Binary / protocol, Android APK, Firmware / UEFI, and a coordinating Team Lead |
| **MCP server** | Local `mcp__uefi__*` tools for triage, firmware parsing, and NVRAM analysis |
| **Analysis playbooks** | Binary/protocol, Android APK, and firmware reverse-engineering workflows |
| **Analysis scripts** | Fifteen standalone Python utilities; JSON output supported |
| **Install model** | One composition bundle for the complete kit, or individual bundles for development |
| **Reporting** | Structured reverse-engineering and security assessments with evidence, severity, confidence, coverage, and limitations |

## Choose your specialist

Install the complete bundle once, then select the preset that fits the task in the DSH Agent selector.

| Preset | Best for | Focus |
|---|---|---|
| **QNX-Agent-二进制逆向** (`reversing`) | Unknown binaries, Android apps, and protocol behavior | PE / ELF / Mach-O / APK triage, app components, DEX, native code, dependencies, packing, crypto, and protocol reversing |
| **QNX-Agent-安卓 APK 逆向** (`android-apk`) | Android APK and app security | APK/split identity, signing, Manifest/components, DEX/Smali, WebView, dependencies/CVEs, JNI/native code, and authorized dynamic analysis |
| **QNX-Agent-固件逆向** (`uefi`) | BIOS images, SPI dumps, and capsules | FV / FFS structure, NVRAM / VSS, SMM triage, boot flow, and trust anchors |
| **QNX-Agent-团队协作** (`reversing-team`) | Multi-layer investigations | Coordinates binary and firmware work, delegates scoped threads, and synthesizes findings |

Each preset loads its matching playbook:

- [Binary and protocol reverse-engineering playbook](.dsh/skills/reverse-engineering/SKILL.md)
- [Android APK reverse-engineering and security playbook](.dsh/skills/android-apk-security/SKILL.md)
- [Firmware and UEFI playbook](.dsh/skills/firmware-uefi/SKILL.md)

## 预设模式与使用方法

在 DSH 的 Agent 选择器中按任务选择预设，然后直接在对话中给出样本路径、分析目标和已知背景。复杂任务可以先说明优先关注的问题；Agent 会根据证据选择工具，并标出未确认的信息。

| 预设 | 模式说明 | 如何使用 |
|---|---|---|
| **QNX-Agent-二进制逆向**（`reversing`） | 通用二进制、Android APK 与协议逆向，适合 PE / ELF / Mach-O / APK、应用组件、DEX/native、依赖漏洞与安全配置分析。 | 选择该预设，提供 APK 或 split 文件路径及分析目标；先识别哈希、包名、版本和签名，再按授权范围做静态分析，动态测试需指定隔离模拟器。 |
| **QNX-Agent-安卓 APK 逆向**（`android-apk`） | Android 应用专项预设，适合 APK、split APK、APKS、XAPK、APKM、AAB 和配套源码，覆盖静态逆向、漏洞验证与移动安全评估。 | 选择该预设，提供应用包路径及关注目标；默认静态分析。动态分析需明确授权范围，并准备隔离、可回滚的 Android 模拟器和测试数据。 |
| **QNX-Agent-固件逆向**（`uefi`） | 固件专用分析，适合 SPI / BIOS 镜像、UEFI Capsule、EC 与嵌入式 SoC，重点覆盖 FV / FFS、NVRAM、SMM 和启动链。 | 选择该预设，提供固件文件、设备型号或平台信息；先识别镜像与区域，再指定关注的驱动、变量或启动阶段。 |
| **QNX-Agent-团队协作**（`reversing-team`） | 多代理协作，适合同时涉及二进制、Android APK、协议和固件，或需要并行调查多个独立问题的任务。 | 选择该预设，说明总目标、样本路径、优先级和操作限制；协调代理拆分独立子任务，再汇总并核对证据。 |

四个预设都支持直接用自然语言提问。提交样本时请明确路径；若只想做静态分析，也请在请求中注明。团队协调模式会在任务确实可拆分时再分派工作。Android APK 分析默认先做静态检查；动态分析只在获授权的隔离模拟器中进行。

## What makes the workflow useful

### Evidence before conclusions

The agent identifies the artifact and architecture before deeper analysis, selects follow-up tools from observed evidence, and treats packer, entropy, and YARA results as leads that need corroboration. Findings distinguish direct observations from interpretation and cite hashes, tool output, GUIDs, offsets, or RVAs where available.

### Detailed reports, not just a verdict

Requested reports use a clear title and metadata header, an executive summary, artifact identity and hashes, scope and methodology, detailed evidence-backed findings, relevant IOC and mapping tables, recommendations, limitations, and useful appendices. Unknown, unavailable, and untested information is labeled instead of guessed. Reports end with:

```text
— QNX-Agent (Copyright Qi-NX)
```

A reusable [report template](templates/reverse-engineering-report.md) includes a finding table and evidence ledger that links claims to artifact hashes, tool output, and addresses.

### Local tools, structured results

The [UEFI MCP server](dsh-uefi-mcp/) exposes the toolkit as local `mcp__uefi__*` tools over stdio. Use them from a preset or run the Python scripts directly; scripts support `--json` for automation. Firmware version comparison covers FV/FFS records and can also compare UEFIExtract output trees by path and SHA-256.

## Toolkit

### Vulnerability scanning and security assessment

QNX-Agent can run installed **OSV-Scanner** for dependency advisories, **Trivy** for dependencies/misconfigurations/secrets, and **Semgrep** for source-code rules. It normalizes Trivy, OSV-Scanner, Semgrep JSON, and SARIF into findings with stable IDs, severity counts, references, and evidence locations. For firmware, it guides image-specific review of Secure Boot, capsule verification/rollback, SPI write protection, SMM input validation, and trust anchors; CHIPSEC results must come from the identified target platform and be corroborated against matching firmware evidence.

Scanner hits remain candidates until affected versions, reachability/configuration, vendor backports, and exploit preconditions are validated. Reports distinguish confirmed issues from unverified leads and state scan coverage and limitations. External scanners may update vulnerability databases or fetch remote rules; the offline assessment parser does not access the network. See the [reverse-engineering playbook](.dsh/skills/reverse-engineering/SKILL.md) and [MCP tool guide](dsh-uefi-mcp/README.md).

| Tool | What it does |
|---|---|
| [`walk_fv.py`](.dsh/skills/firmware-uefi/scripts/walk_fv.py) | Walk firmware volumes, FFS files, and sections; optionally extract PE32 / TE sections |
| [`extract_vss.py`](.dsh/skills/firmware-uefi/scripts/extract_vss.py) | Locate, validate, and carve candidate UEFI variable stores |
| [`vss_parse.py`](.dsh/skills/firmware-uefi/scripts/vss_parse.py) | Decode variables and identify Secure Boot-related records and state |
| [`list_smi.py`](.dsh/skills/firmware-uefi/scripts/list_smi.py) | Enumerate SMM modules and dispatch markers for follow-up analysis |
| [`uefi_walk.py`](.dsh/skills/firmware-uefi/scripts/uefi_walk.py) | Dependency-light fallback firmware-volume scanner |
| [`chipsec_abstract.py`](.dsh/skills/firmware-uefi/scripts/chipsec_abstract.py) | Normalize CHIPSEC logs into structured JSON |
| [`firmware_diff.py`](.dsh/skills/firmware-uefi/scripts/firmware_diff.py) | Compare firmware FV/FFS inventories or extracted payload trees by identity and hash |
| [`lief_info.py`](.dsh/skills/reverse-engineering/scripts/lief_info.py) | Identify PE / ELF / Mach-O metadata, sections, imports, and exports |
| [`pack_detect.py`](.dsh/skills/reverse-engineering/scripts/pack_detect.py) | Assess packer / protector indicators using multiple heuristics |
| [`yara_scan.py`](.dsh/skills/reverse-engineering/scripts/yara_scan.py) | Scan built-in triage rules or a supplied YARA ruleset |
| [`yara_backtest.py`](.dsh/skills/reverse-engineering/scripts/yara_backtest.py) | Compile and backtest YARA rules against explicitly labeled corpus samples |
| [`ghidra_evidence.py`](.dsh/skills/reverse-engineering/scripts/ghidra_evidence.py) | Export Ghidra functions and callsites linked to addresses and image offsets |
| [`dynamic_evidence.py`](.dsh/skills/reverse-engineering/scripts/dynamic_evidence.py) | Normalize existing CAPE/Cuckoo, Sysmon, and Procmon telemetry exports |
| [`vulnerability_scan.py`](.dsh/skills/reverse-engineering/scripts/vulnerability_scan.py) | Run installed OSV-Scanner, Trivy, or Semgrep against a local target and normalize results |
| [`security_assessment.py`](.dsh/skills/reverse-engineering/scripts/security_assessment.py) | Convert scanner JSON/SARIF into a bounded finding/evidence ledger and risk summary |

### Android APK reverse engineering and mobile security

The [Android APK playbook](.dsh/skills/android-apk-security/SKILL.md) guides the Agent through APK/APKS/XAPK/AAB identification, split and signing inventory, manifest and permission review, exported components and deep links, WebView and network configuration, data storage, dependencies, DEX/Smali, and JNI/native libraries. It defines when to use Android SDK tools, `apksigner`, apktool, JADX, MobSF, ADB, an isolated emulator, Frida, and the existing vulnerability-assessment tools.

The playbook distinguishes static leads from verified vulnerabilities, requires exact component/version and reachability evidence for CVE claims, and records device/API-level limits. Dynamic analysis is scoped to authorized targets and disposable test environments. Use the [Android APK security report template](templates/android-apk-security-report.md) for a complete assessment.

The MCP server also provides availability checks, binary triage, signature scans, firmware parsing, extraction, vulnerability scanning, and offline security assessment. Optional [`osv-scanner`](https://google.github.io/osv-scanner/installation/), [Trivy](https://www.trivy.dev/docs/latest/getting-started/), and [Semgrep](https://docs.semgrep.dev/getting-started/quickstart) executables must be installed separately. Scans can contact advisory databases or rule registries, depending on scanner configuration; review data-handling requirements for confidential code. Raw saved scanner reports may contain sensitive matches. See the [MCP server guide](dsh-uefi-mcp/README.md) for the complete tool list and manifest format.

## Install

### Option A — Install the complete kit (recommended)

In the DSH plugin manager, install the GitHub bundle:

```text
plugin_manager  action=install_bundle  target=github:Shiyou-Qi/Qi-NX-Agent
```

The root `package.json` composes the four presets and the MCP bundle into one install target.

### Option B — Install one bundle while developing

```text
plugin_manager  action=install_bundle  target=<absolute path to a bundle directory>
```

Available bundle directories: `dsh-reversing-preset`, `dsh-android-apk-preset`, `dsh-uefi-preset`, `dsh-reversing-team-preset`, and `dsh-uefi-mcp`. The standalone Android preset provides its own persona and Android playbook access; install the complete root bundle to include the shared MCP tools as well.

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
| **Ghidra** | Function and callsite evidence | Install Ghidra and expose `analyzeHeadless` on `PATH`, set `GHIDRA_HOME`, or set `GHIDRA_ANALYZE_HEADLESS`; analysis is static |
| **Android SDK (`apkanalyzer`, `aapt2`, `apksigner`)** | APK metadata, manifest, permissions, and signing certificate verification | Install Android SDK command-line tools and confirm the executable paths |
| **JADX / apktool** | DEX-to-source view; resource, Manifest, and Smali decoding | Decompilation can be incomplete; verify important paths against Smali/DEX |
| **MobSF** | Mobile application static analysis and optional dynamic analysis | Keep sensitive APKs in a locally controlled deployment; dynamic analysis requires a configured emulator |
| **ADB / Android Emulator / Frida** | Authorized runtime and instrumentation evidence | Use a disposable emulator, snapshot it, and use synthetic test data |
| **CAPE / Cuckoo, Sysmon, Procmon** | Runtime behavior telemetry | Run samples only in an isolated disposable sandbox/VM, export logs, then use `dynamic_evidence` to normalize them offline |

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
├── dsh-android-apk-preset/         Android APK reverse-engineering preset
├── dsh-uefi-preset/                Firmware / UEFI preset
├── dsh-reversing-team-preset/      Coordinating Team Lead preset
├── dsh-uefi-mcp/                   Local MCP server and bundle
├── .dsh/skills/                    Binary, Android APK, and firmware playbooks/utilities
└── tests/                          Fixtures and verification suite
```

## Scope and limitations

- **Heuristics are not verdicts.** A packer or YARA hit is a lead; no known indicator does not establish that a file is clean.
- **Firmware extraction has boundaries.** `walk_fv` identifies compressed and GUID-defined sections but does not decompress them; use `uefi_firmware_parse` for decompression-aware inventory or UEFIExtract when you need extracted bytes, then triage the output again.
- **Some attribution needs reference data.** `list_smi` does not hardcode protocol GUIDs. Supply an authoritative `guids.csv` for GUID attribution; otherwise findings are based on structural and string-marker evidence.
- **NVRAM can contain historical records.** `vss_parse` marks the selected current copy. Deleted records can be useful forensic evidence, but are not live configuration.
- **SMM inventory is not handler recovery.** `list_smi` finds modules and dispatch markers; use a disassembler to recover handler inputs and validate behavior.
- **Hostile artifacts require isolation.** Do not execute malware-class samples on the host. Use a sandbox or VM; firmware flashing belongs on a sacrificial, recoverable target.

## Troubleshooting preset activation

If presets stop loading, inspect `$DSH_HOME/profiles/<profile>/cordis.yml`. The profile root should remain an empty entry list (`[]`); bundle patches build the tree. A populated profile root can duplicate inserted rows and cause activation failures. Restore the empty list and let the bundle patches rebuild the profile.

---

<div align="center">

**QNX-Agent · Copyright Qi-NX**<br />
Built for careful analysis. Ground conclusions in evidence.

</div>
