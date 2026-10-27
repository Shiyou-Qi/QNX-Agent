"""Optional APK doctor, comparison, explicit emulator session, and report builder."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import android_apk_analyze as engine

BANNER = "— QNX-Agent (Copyright Qi-NX)"
PACKAGE_RE = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$")
REDACT_RE = re.compile(r"(?i)(api[_-]?key|client[_-]?secret|password|access[_-]?token|secret)\s*[:=]\s*([^\s,;]{8,})")


def _run(exe: str, args: list[str], timeout: int = 20) -> dict:
    try:
        result = subprocess.run([exe, *args], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, check=False, shell=False)
        return {"exit_code": result.returncode,
                "stdout": result.stdout[:65536].decode("utf-8", "replace"),
                "stderr": result.stderr[-4096:].decode("utf-8", "replace"),
                "truncated": len(result.stdout) > 65536}
    except subprocess.TimeoutExpired:
        return {"error": f"timeout after {timeout}s"}
    except OSError as exc:
        return {"error": exc.__class__.__name__}


def tool_doctor() -> dict:
    candidates = {
        "apkanalyzer": ["apkanalyzer"],
        "aapt2": ["aapt2", "aapt2.exe"],
        "apksigner": ["apksigner", "apksigner.bat"],
        "apktool": ["apktool", "apktool.exe"],
        "jadx": ["jadx", "jadx.exe"],
        "adb": ["adb", "adb.exe"],
        "emulator": ["emulator", "emulator.exe"],
        "osv-scanner": ["osv-scanner", "osv-scanner.exe"],
        "trivy": ["trivy", "trivy.exe"],
        "syft": ["syft", "syft.exe"],
        "frida": ["frida", "frida.exe"],
    }
    tools = {}
    for name, alternatives in candidates.items():
        command = engine._tool_command(name) if name in {"apkanalyzer", "apktool", "jadx", "apksigner"} else None
        path = next((shutil.which(item) for item in alternatives if shutil.which(item)), None)
        if path and Path(path).suffix.lower() in {".bat", ".cmd"}:
            path = None
        resolved = command or ([path] if path else None)
        tools[name] = {"status": "available" if resolved else "unavailable",
                       "command": resolved}
        if resolved:
            args = ["--version"] if name not in {"adb", "emulator"} else ["version"]
            version = engine._run_tool(resolved, args, timeout=20)
            tools[name]["version_output"] = (version.get("stdout") or version.get("stderr", "")).strip()[:300]
    sdk_root = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
    devices = {"status": "unavailable", "emulators": []}
    adb = (tools["adb"].get("command") or [None])[0]
    if adb:
        listing = _run(adb, ["devices", "-l"])
        emulators = []
        if listing.get("exit_code") == 0:
            for line in listing.get("stdout", "").splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 2 and parts[0].startswith("emulator-") and parts[1] == "device":
                    emulators.append(parts[0])
        devices = {"status": "available" if listing.get("exit_code") == 0 else "error",
                   "emulators": emulators}
    return {"generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "android_sdk_root": sdk_root, "tools": tools, "adb_emulators": devices,
            "analysis_boundary": "Doctor performs version/device enumeration only; it does not install or launch an APK."}


def _finding_key(finding: dict) -> tuple:
    return (finding.get("category"), finding.get("title"), finding.get("evidence"))


def compare_apks(before: str, after: str, deep_analysis: bool = False,
                 isolated_tooling_confirmed: bool = False) -> dict:
    old = engine.analyze(before, deep_analysis=deep_analysis,
                         isolated_tooling_confirmed=isolated_tooling_confirmed)
    new = engine.analyze(after, deep_analysis=deep_analysis,
                         isolated_tooling_confirmed=isolated_tooling_confirmed)
    if "error" in old or "error" in new:
        return {"error": "one or both APKs could not be analyzed", "before_error": old.get("error"),
                "after_error": new.get("error"), "author": engine.BANNER}
    old_members = {item["name"]: item for item in old.get("archive", {}).get("members", [])}
    new_members = {item["name"]: item for item in new.get("archive", {}).get("members", [])}
    added = sorted(new_members.keys() - old_members.keys())
    removed = sorted(old_members.keys() - new_members.keys())
    changed = sorted(name for name in old_members.keys() & new_members.keys()
                     if old_members[name].get("sha256") != new_members[name].get("sha256")
                     and (old_members[name].get("sha256") or new_members[name].get("sha256")))
    old_findings = {_finding_key(item): item for item in old.get("findings", [])}
    new_findings = {_finding_key(item): item for item in new.get("findings", [])}
    old_deps = {item["purl"] for item in old.get("dependency_analysis", {}).get("components", [])}
    new_deps = {item["purl"] for item in new.get("dependency_analysis", {}).get("components", [])}
    old_manifest = old.get("manifest") or {}
    new_manifest = new.get("manifest") or {}
    manifest_fields = ("package", "version_name", "version_code", "min_sdk", "target_sdk", "permissions", "components", "application_attributes")
    manifest_changes = {field: {"before": old_manifest.get(field), "after": new_manifest.get(field)}
                        for field in manifest_fields if old_manifest.get(field) != new_manifest.get(field)}
    return {"analysis": "static-version-comparison", "before": {"path": old.get("target"), "sha256": old.get("sha256")},
            "after": {"path": new.get("target"), "sha256": new.get("sha256")},
            "manifest_changes": manifest_changes,
            "archive_changes": {"added": added[:500], "removed": removed[:500], "changed": changed[:500],
                                "truncated": any(len(items) > 500 for items in (added, removed, changed))},
            "dependency_changes": {"added": sorted(new_deps - old_deps), "removed": sorted(old_deps - new_deps)},
            "finding_changes": {"new_candidates": [list(item) for item in sorted(new_findings.keys() - old_findings.keys(), key=str)],
                                "no_longer_observed": [list(item) for item in sorted(old_findings.keys() - new_findings.keys(), key=str)]},
            "interpretation": "Differences identify changes for review; they do not establish that a new build is safer or more vulnerable.",
            "author": engine.BANNER}


def dynamic_emulator_session(apk: str, package_name: str, device_serial: str,
                             authorized: bool, isolated_emulator_confirmed: bool,
                             observation_seconds: int = 15) -> dict:
    """Install/launch only on a confirmed Android emulator, with explicit opt-in flags."""
    if not authorized or not isolated_emulator_confirmed:
        return {"error": "explicit authorization and isolated_emulator_confirmed are required", "author": engine.BANNER}
    if not PACKAGE_RE.fullmatch(package_name):
        return {"error": "invalid Android package name", "author": engine.BANNER}
    if not re.fullmatch(r"emulator-[0-9]+", device_serial):
        return {"error": "only emulator-<port> ADB serials are accepted", "author": engine.BANNER}
    if Path(apk).suffix.lower() != ".apk":
        return {"error": "dynamic install currently accepts one .apk file; split packages require an explicit install-multiple workflow", "author": engine.BANNER}
    seconds = max(1, min(int(observation_seconds), 60))
    adb = next((shutil.which(name) for name in ("adb", "adb.exe") if shutil.which(name)), None)
    if not adb:
        return {"error": "adb is unavailable", "author": engine.BANNER}
    apk_path = Path(apk).expanduser().resolve()
    preliminary = engine.analyze(str(apk_path), deep_analysis=False)
    if preliminary.get("error"):
        return {"error": preliminary["error"], "author": engine.BANNER}
    manifest_package = (preliminary.get("manifest") or {}).get("package")
    if manifest_package and manifest_package != package_name:
        return {"error": "provided package name does not match decoded APK manifest", "manifest_package": manifest_package,
                "author": engine.BANNER}
    serial = ["-s", device_serial]
    state = _run(adb, [*serial, "get-state"])
    emu = _run(adb, [*serial, "shell", "getprop", "ro.kernel.qemu"])
    if state.get("exit_code") != 0 or state.get("stdout", "").strip() != "device" or emu.get("stdout", "").strip() != "1":
        return {"error": "ADB target did not positively identify as a running emulator", "device_state": state,
                "qemu_property": emu, "author": engine.BANNER}
    started_at = datetime.now(timezone.utc).isoformat()
    sdk = _run(adb, [*serial, "shell", "getprop", "ro.build.version.sdk"])
    abi = _run(adb, [*serial, "shell", "getprop", "ro.product.cpu.abi"])
    install = _run(adb, [*serial, "install", str(apk_path)], timeout=180)
    if install.get("exit_code") != 0:
        return {"error": "emulator install failed", "install": install,
                "sample_sha256": preliminary.get("sha256"), "author": engine.BANNER}
    launch = _run(adb, [*serial, "shell", "monkey", "-p", package_name, "1"], timeout=30)
    if launch.get("exit_code") != 0:
        return {"error": "launch attempt failed", "install": install, "launch": launch,
                "sample_sha256": preliminary.get("sha256"), "author": engine.BANNER}
    time.sleep(seconds)
    pid_result = _run(adb, [*serial, "shell", "pidof", package_name])
    pids = pid_result.get("stdout", "").split()
    logs = (_run(adb, [*serial, "logcat", "-d", "--pid", pids[0], "-v", "threadtime", "-t", "1000"], timeout=30)
            if pids else {"status": "unavailable", "stderr": "app process was not running at capture time"})
    finished_at = datetime.now(timezone.utc).isoformat()
    log_text = REDACT_RE.sub(r"\1=[REDACTED]", logs.get("stdout", ""))
    log_text = re.sub(r"(?i)(https?://[^\s?]+\?)[^\s]+", r"\1[REDACTED]", log_text)
    return {"analysis": "authorized-emulator-install-launch-observation", "sample_sha256": preliminary.get("sha256"),
            "package_name": package_name, "device_serial": device_serial,
            "device_facts": {"qemu": "1", "state": "device",
                             "android_api_level": sdk.get("stdout", "").strip(),
                             "primary_abi": abi.get("stdout", "").strip()},
            "started_at_utc": started_at, "finished_at_utc": finished_at,
            "observation_seconds": seconds,
            "install": install, "launch": launch,
            "process_id_at_capture": pids[0] if pids else None,
            "logcat": {"exit_code": logs.get("exit_code"), "text_redacted": log_text[-24000:],
                       "truncated": len(logs.get("stdout", "")) > 24000},
            "limitations": ["This performs only install, launcher start, and bounded log capture; it is not a complete dynamic security test.",
                            "The emulator must be disposable and contain no real user accounts or sensitive data.",
                            "Network traffic, app-private files, API behavior, and native instrumentation are not collected by this action.",
                            "The installed APK remains on the emulator after collection; clean up using the disposable emulator snapshot/reset."],
            "author": engine.BANNER}


def _md(value) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _safe_web_url(value: str) -> str | None:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return value.replace("<", "%3C").replace(">", "%3E").replace(")", "%29")


def build_report(analysis: dict, dynamic: dict | None = None, language: str = "zh",
                 authorization_scope: str = "未由分析引擎记录；需由委托方补充") -> str:
    zh = language.lower().startswith("zh")
    title = "Android APK 逆向与安全评估报告" if zh else "Android APK Reverse Engineering and Security Assessment"
    lines = [f"# {title}", "", f"- 报告生成时间（UTC）：{datetime.now(timezone.utc).isoformat()}",
             f"- 分析员：QNX-Agent；授权与范围：{_md(authorization_scope)}",
             f"- 样本：`{_md(analysis.get('file_name') or analysis.get('target'))}`",
             f"- SHA-256：`{_md(analysis.get('sha256'))}`", f"- 分析状态：{_md(analysis.get('analysis'))}", "",
             "## 1. 执行摘要" if zh else "## 1. Executive Summary", "",
             f"发现候选项：{analysis.get('finding_count', 0)}；最高扫描等级：{_md(analysis.get('scanner_reported_max_severity') or '未定')}。" if zh else
             f"Candidate findings: {analysis.get('finding_count', 0)}; highest reported severity: {_md(analysis.get('scanner_reported_max_severity') or 'undetermined')}.",
             "此报告区分直接观察与待验证线索；静态未发现问题不代表应用安全。" if zh else
             "This report separates observations from unverified leads; no static findings do not prove the application is secure.", "",
             "## 2. 样本与包身份" if zh else "## 2. Sample and Package Identity", "",
             "| 字段 | 结果 |", "|---|---|",
             f"| 文件大小 | {_md(analysis.get('file_size'))} bytes |",
             f"| 容器类型 | {_md(analysis.get('package_container'))} |",
             f"| 包名 | {_md((analysis.get('manifest') or {}).get('package') or '未解析')} |",
             f"| 版本 | {_md((analysis.get('manifest') or {}).get('version_name'))} / {_md((analysis.get('manifest') or {}).get('version_code'))} |",
             f"| SDK | min {_md((analysis.get('manifest') or {}).get('min_sdk'))} / target {_md((analysis.get('manifest') or {}).get('target_sdk'))} |",
             f"| 签名校验 | {_md((analysis.get('signing') or {}).get('exit_code', (analysis.get('signing') or {}).get('status', '未验证')))} |",
             f"| 签名工具证书摘要 | {_md((analysis.get('signing') or {}).get('stdout', '不可用或未输出'))[:1200]} |", "",
             "## 3. 覆盖范围与工具" if zh else "## 3. Coverage and Tools", "",
             f"容器条目 {((analysis.get('archive') or {}).get('entry_count', 0))}；已纳入 {((analysis.get('archive') or {}).get('file_count_included', 0))}；DEX 字符串线索 {((analysis.get('dex_analysis') or {}).get('clue_count', 0))}。", "",
             "| 工具 | 状态 | 版本 / 结果 |", "|---|---|---|"]
    for key, result in (analysis.get("code_analysis") or {}).items():
        lines.append(f"| {key} | {_md(result.get('status'))} | {_md(result.get('version') or result.get('reason') or result.get('error') or '未记录')} |")
    for name, result in (analysis.get("tool_results") or {}).items():
        if isinstance(result, dict):
            lines.append(f"| {name} | {_md(result.get('exit_code', result.get('status', '未运行')))} | {_md(result.get('stderr') or result.get('reason') or '')[:300]} |")
    lines += ["", "## 4. 应用攻击面" if zh else "## 4. Application Attack Surface", "",
              "### 权限", "", "| 权限 | maxSdkVersion |", "|---|---|"]
    for permission in (analysis.get("manifest") or {}).get("permissions", []):
        lines.append(f"| {_md(permission.get('name'))} | {_md(permission.get('max_sdk_version'))} |")
    if not (analysis.get("manifest") or {}).get("permissions"):
        lines.append("| 未解析 / 未声明 | — |")
    lines += ["", "### 导出组件", "", "| 类型 | 名称 | exported | 权限 | intent filters |", "|---|---|---|---|---:|"]
    for component in (analysis.get("manifest") or {}).get("components", []):
        lines.append(f"| {_md(component.get('type'))} | {_md(component.get('name'))} | {_md(component.get('exported') or '平台默认/未知')} | {_md(component.get('permission'))} | {_md(component.get('intent_filter_count'))} |")
    if not (analysis.get("manifest") or {}).get("components"):
        lines.append("| 未解析 / 未声明 | — | — | — | — |")
    native_libs = [item for item in (analysis.get("archive") or {}).get("members", []) if item.get("kind") == "native-library"]
    lines += ["", "### Native libraries", "", "| 文件 | ABI / ELF machine | SHA-256 |", "|---|---|---|"]
    for item in native_libs[:300]:
        elf = item.get("elf") or {}
        lines.append(f"| `{_md(item.get('name'))}` | {_md(elf.get('abi_path_hint'))} / {_md(elf.get('machine'))} | `{_md(item.get('sha256'))}` |")
    if not native_libs:
        lines.append("未发现或未纳入 native `.so` 文件。")
    lines += ["", "## 5. 安全发现" if zh else "## 5. Security Findings", "",
             "| F-ID | 等级 | MASVS 区域 | MASTG 测试参考 | 状态 | 标题 | 证据 |", "|---|---|---|---|---|---|---|"]
    for finding in analysis.get("findings", []):
        refs = ", ".join(f"[{ref['id']}]({ref['url']})" for ref in finding.get("mastg_references", [])) or "未直接映射"
        lines.append(f"| {_md(finding.get('finding_id'))} | {_md(finding.get('severity'))} | {_md(finding.get('masvs_area'))} | {refs} | {_md(finding.get('status'))} | {_md(finding.get('title'))} | {_md(finding.get('evidence'))} |")
    if not analysis.get("findings"):
        lines.append("| — | — | — | 未报告 | 当前覆盖内无候选发现 | 这不是安全结论 |")
    for finding in analysis.get("findings", []):
        lines += ["", f"### {finding.get('finding_id')} — {finding.get('title')}", "",
                  f"- **类别 / MASVS：** {finding.get('category')} / {finding.get('masvs_area')}",
                  f"- **MASTG 参考：** {', '.join(ref.get('id', '') for ref in finding.get('mastg_references', [])) or '未直接映射；需选择适用测试项'}",
                  f"- **事实证据：** {finding.get('evidence')}", f"- **分析说明：** {finding.get('detail')}",
                  f"- **修复建议（验证后适用）：** {finding.get('remediation', '确认影响后按最小权限修复。')}",
                  f"- **状态与置信度：** {finding.get('status')} / {finding.get('confidence')}"]
        if finding.get("advisory_id"):
            lines += [f"- **公告：** {finding.get('advisory_id')}；别名：{', '.join(finding.get('aliases', [])) or '无'}；CVSS：{finding.get('cvss_score') if finding.get('cvss_score') is not None else '未提供可解析分数'}",
                      f"- **修复版本：** {', '.join(finding.get('fixed_versions', [])) or '公告未给出'}"]
            lines.extend(f"- **参考：** {safe_url}" for url in finding.get("references", [])
                         if (safe_url := _safe_web_url(url)))
    lines += ["", "## 6. DEX / 代码分析" if zh else "## 6. DEX / Code Analysis", ""]
    for key, result in (analysis.get("code_analysis") or {}).items():
        lines.append(f"- **{key}：** {result.get('status')}；扫描文件 {result.get('files_scanned', 0)}；候选项 {result.get('finding_count', 0)}")
        hits = result.get("findings", []) or (result.get("smali_analysis") or {}).get("findings", [])
        for hit in hits[:100]:
            lines.append(f"  - `{hit.get('file')}:{hit.get('line')}` `{hit.get('rule_id')}`：`{_md(hit.get('evidence_excerpt_redacted'))}`（{hit.get('status')}）")
    for name, result in (analysis.get("tool_results") or {}).items():
        if isinstance(result, dict):
            lines.append(f"- **工具 {name}：** exit={result.get('exit_code', result.get('status', '未运行'))}; version={result.get('version', '未记录')}")
    for clue in (analysis.get("dex_analysis") or {}).get("string_clues", [])[:100]:
        lines.append(f"- `{_md(clue.get('member'))}+0x{clue.get('string_data_offset', 0):x}` `{', '.join(clue.get('indicators', []))}`：`{_md(clue.get('value_redacted'))}`")
    deps = analysis.get("dependency_analysis") or {}
    lines += ["", "## 7. 依赖清单与 CVE" if zh else "## 7. Dependencies and CVEs", "",
              f"精确 Maven 组件数：{deps.get('component_count', 0)}；OSV 扫描状态：{(deps.get('osv_scan') or {}).get('status', '未运行')}。", "",
              "| 组件 | 版本 | PURL | 来源 |", "|---|---|---|---|"]
    for component in deps.get("components", [])[:300]:
        lines.append(f"| {_md(component.get('name'))} | {_md(component.get('version'))} | `{_md(component.get('purl'))}` | {_md(component.get('evidence'))} |")
    osv = deps.get("osv_scan") or {}
    if osv.get("report"):
        lines += ["", "OSV 原始 JSON 扫描结果（节选）:", "", "```json", osv["report"][:12000], "```"]
    lines += ["", "## 8. 动态分析" if zh else "## 8. Dynamic Analysis", ""]
    if dynamic:
        facts = dynamic.get("device_facts") or {}
        lines.append(f"- 流程：{dynamic.get('analysis', '—')}；设备：{dynamic.get('device_serial', '—')}；Android API：{facts.get('android_api_level', '未知')}；ABI：{facts.get('primary_abi', '未知')}；观察秒数：{dynamic.get('observation_seconds', '—')}")
        lines.append(f"- 时间：{dynamic.get('started_at_utc', '未知')} — {dynamic.get('finished_at_utc', '未知')}")
        lines += ["- 日志摘要（已脱敏，节选）：", "", "```text",
                  (dynamic.get("logcat") or {}).get("text_redacted", "")[:4000], "```"]
        for limitation in dynamic.get("limitations", []):
            lines.append(f"- 限制：{limitation}")
    else:
        lines.append("未执行动态分析。")
    lines += ["", "## 9. 限制与未检查项" if zh else "## 9. Limitations and Untested Areas", ""]
    for item in analysis.get("limitations", []):
        lines.append(f"- {item}")
    for item in (analysis.get("archive") or {}).get("warnings", []):
        lines.append(f"- {item}")
    lines += ["", "## 10. 证据台账" if zh else "## 10. Evidence Ledger", "",
              "| E-ID | 样本 SHA-256 | 工具/位置 | 观察 |", "|---|---|---|---|"]
    for finding in analysis.get("findings", []):
        lines.append(f"| {_md(finding.get('evidence_id'))} | `{_md(analysis.get('sha256'))}` | {_md(finding.get('evidence'))} | {_md(finding.get('title'))} |")
    lines += ["", "— QNX-Agent (Copyright Qi-NX)", ""]
    return "\n".join(lines)


def write_report(target: str, output_path: str | None = None, language: str = "zh",
                 deep_analysis: bool = False, isolated_tooling_confirmed: bool = False,
                 scan_vulnerabilities: bool = False,
                 dynamic_json: str | None = None,
                 authorization_scope: str = "未由分析引擎记录；需由委托方补充") -> dict:
    analysis = engine.analyze(target, deep_analysis=deep_analysis,
                              isolated_tooling_confirmed=isolated_tooling_confirmed,
                              scan_vulnerabilities=scan_vulnerabilities)
    if analysis.get("error"):
        return {"error": analysis["error"], "author": engine.BANNER}
    dynamic = json.loads(dynamic_json) if dynamic_json else None
    if dynamic is not None and not isinstance(dynamic, dict):
        return {"error": "dynamic_json must be a JSON object", "author": engine.BANNER}
    report = build_report(analysis, dynamic, language, authorization_scope)
    if output_path:
        destination = Path(output_path).expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            with destination.open("x", encoding="utf-8") as stream:
                stream.write(report)
        except FileExistsError:
            return {"error": "refusing to overwrite an existing report", "output_path": str(destination),
                    "author": engine.BANNER}
        return {"output_path": str(destination), "sha256": hashlib.sha256(report.encode("utf-8")).hexdigest(),
                "report": report, "author": engine.BANNER}
    return {"report": report, "sha256": hashlib.sha256(report.encode("utf-8")).hexdigest(),
            "author": engine.BANNER}
