#!/usr/bin/env python3
"""Bounded Android package inventory and security-candidate analysis.

The default path uses Python's ZIP reader and never extracts, installs, or
executes app code. Optional external parsers require an explicit isolated-tooling
confirmation; JADX/APKTool output is confined to temporary directories.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import quote

BANNER = "by QNX-Agent (Copyright Qi-NX)"
MAX_APK_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 30_000
MAX_EXPANDED_BYTES = 8 * 1024 * 1024 * 1024
MAX_MEMBER_HASH_BYTES = 256 * 1024 * 1024
MAX_TOTAL_MEMBER_HASH_BYTES = 1024 * 1024 * 1024
MAX_DEX_SCAN_BYTES = 128 * 1024 * 1024
MAX_DEX_STRINGS = 250_000
MAX_DEX_FILES_SCANNED = 64
MAX_TOOL_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_DECOMPILED_FILES = 20_000
MAX_CODE_FINDINGS = 500
MAX_DECOMPILED_SOURCE_BYTES = 512 * 1024 * 1024
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
COMPONENT_TAGS = {"activity", "activity-alias", "service", "receiver", "provider"}
DEX_CLUE_PATTERNS = {
    "network-endpoint": re.compile(r"https?://[^\s\"'<>\\]{6,300}", re.IGNORECASE),
    "webview-bridge-or-script": re.compile(r"addJavascriptInterface|setJavaScriptEnabled|onReceivedSslError", re.IGNORECASE),
    "tls-validation": re.compile(r"TrustManager|HostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|SSLContext", re.IGNORECASE),
    "dynamic-code-loading": re.compile(r"DexClassLoader|InMemoryDexClassLoader|PathClassLoader", re.IGNORECASE),
    "command-execution": re.compile(r"Runtime;->exec|ProcessBuilder|java/lang/Runtime", re.IGNORECASE),
    "sensitive-storage-or-data": re.compile(r"MODE_WORLD_(READABLE|WRITEABLE)|getExternalStorageDirectory|SharedPreferences", re.IGNORECASE),
    "sensitive-api": re.compile(r"SmsManager|AccessibilityService|ClipboardManager|TelephonyManager", re.IGNORECASE),
}
SECRET_PATTERN = re.compile(r"(?i)(api[_-]?key|client[_-]?secret|password|access[_-]?token|secret)\s*[:=]\s*([^\s,;]{8,})")
CODE_RULES = (
    ("webview-javascript-bridge", "platform", re.compile(r"addJavascriptInterface\s*\("), "Review bridge exposure, origin validation, and reachable JavaScript-controlled methods."),
    ("webview-debugging", "platform", re.compile(r"setWebContentsDebuggingEnabled\s*\(\s*true"), "Confirm debugging is disabled in release builds."),
    ("unsafe-tls-callback", "network", re.compile(r"onReceivedSslError\s*\([^)]*\)\s*\{[^}]{0,600}handler\.proceed\s*\(", re.DOTALL), "Trace whether certificate errors are bypassed on a reachable WebView path."),
    ("trust-all-tls", "network", re.compile(r"checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier\([^)]*ALLOW_ALL", re.DOTALL), "Validate the trust implementation and the network clients that use it."),
    ("dynamic-code-loading", "code", re.compile(r"(DexClassLoader|InMemoryDexClassLoader|PathClassLoader)\s*\("), "Identify loaded code source, signature/integrity checks, and whether the path is attacker-controlled."),
    ("process-execution", "code", re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\("), "Check command construction, input validation, and reachable caller paths."),
    ("world-readable-writable-mode", "storage", re.compile(r"MODE_WORLD_(READABLE|WRITEABLE)"), "Review whether sensitive data is exposed across app boundaries."),
    ("weak-random", "crypto", re.compile(r"new\s+java\.util\.Random\s*\(|Math\.random\s*\("), "Determine whether randomness protects secrets, tokens, keys, or security decisions."),
    ("static-secret-candidate", "crypto", SECRET_PATTERN),
)
MASVS_AREAS = {
    "platform": "MASVS-PLATFORM", "network": "MASVS-NETWORK",
    "storage": "MASVS-STORAGE", "crypto": "MASVS-CRYPTO",
    "code": "MASVS-CODE", "application-configuration": "MASVS-RESILIENCE",
    "transport-security": "MASVS-NETWORK", "data-protection": "MASVS-STORAGE",
    "component-exposure": "MASVS-PLATFORM", "signing-integrity": "MASVS-RESILIENCE",
}
REMEDIATION_HINTS = {
    "application-configuration": "按发布基线关闭调试/测试标志，并验证正式构建产物。",
    "transport-security": "敏感流量强制使用 TLS；检查 Network Security Config、证书校验和真实调用路径。",
    "data-protection": "按业务威胁模型收紧备份规则，敏感数据使用合适的加密与访问控制。",
    "component-exposure": "为外部组件实施最小权限与服务端/组件内授权，并验证所有输入。",
    "signing-integrity": "用可信发布证书重新签名，并与可信基线证书摘要核对。",
    "webview-javascript-bridge": "移除不必要的 JavaScript bridge，限制可信来源并对桥接方法做细粒度授权。",
    "webview-debugging": "仅在受控调试构建启用 WebView 调试，发布构建显式关闭。",
    "unsafe-tls-callback": "拒绝无效证书并修复信任链；不要在回调中继续处理证书错误。",
    "trust-all-tls": "使用平台默认信任管理器和主机名验证器，移除信任所有实现。",
    "dynamic-code-loading": "验证动态代码来源、签名和完整性；限制可写路径中的代码加载。",
    "process-execution": "避免拼接 shell 命令；使用固定参数 API 并验证不可信输入。",
    "world-readable-writable-mode": "使用应用私有存储或受控 ContentProvider，移除跨应用世界可读写模式。",
    "weak-random": "安全敏感随机值使用 SecureRandom 或 Android Keystore，不用普通 Random/Math.random。",
    "static-secret-candidate": "轮换暴露凭据并移至服务端或受保护密钥存储；客户端混淆不能保护长期密钥。",
}
MASTG_REFERENCES = {
    "android-debuggable": [{"id": "MASTG-TEST-0226", "url": "https://mas.owasp.org/MASTG-TEST-0226/"}],
    "android-cleartext": [{"id": "MASTG-TEST-0235", "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0235/"}],
    "android-backup": [{"id": "MASTG-TEST-0216", "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0216/"}],
    "webview-javascript-bridge": [{"id": "MASTG-TEST-0334", "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0334/"}],
}
ELF_MACHINES = {3: "x86", 40: "ARM", 62: "x86_64", 183: "AArch64", 243: "RISC-V"}


def _sha256_stream(stream, limit: int | None = None) -> tuple[str | None, int]:
    digest = hashlib.sha256()
    size = 0
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        size += len(chunk)
        if limit is not None and size > limit:
            return None, size
        digest.update(chunk)
    return digest.hexdigest(), size


def _uleb128(data: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    for _ in range(5):
        if offset >= len(data):
            raise ValueError("truncated DEX ULEB128")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7f) << shift
        if byte < 0x80:
            return result, offset
        shift += 7
    raise ValueError("invalid DEX ULEB128")


def _dex_clues(data: bytes, member_name: str) -> tuple[list[dict], int, bool]:
    """Extract bounded DEX string-pool clues; strings are leads, not code paths."""
    if len(data) < 112 or not data.startswith(b"dex\n"):
        return [], 0, False
    string_count = int.from_bytes(data[56:60], "little")
    string_ids_off = int.from_bytes(data[60:64], "little")
    if string_count > MAX_DEX_STRINGS or string_ids_off + string_count * 4 > len(data):
        return [], string_count, True
    clues: list[dict] = []
    for index in range(string_count):
        id_offset = string_ids_off + index * 4
        string_off = int.from_bytes(data[id_offset:id_offset + 4], "little")
        if string_off >= len(data):
            continue
        try:
            _, value_offset = _uleb128(data, string_off)  # UTF-16 length prefix
        except ValueError:
            continue
        terminator = data.find(b"\x00", value_offset, min(len(data), value_offset + 16_384))
        if terminator < 0:
            continue
        raw = data[value_offset:terminator].replace(b"\xc0\x80", b"\x00")
        value = raw.decode("utf-8", "replace")
        indicators = [name for name, pattern in DEX_CLUE_PATTERNS.items()
                      if pattern.search(value)]
        secret_match = SECRET_PATTERN.search(value)
        if not indicators and not secret_match:
            continue
        if secret_match:
            indicators.append("possible-hardcoded-secret")
        redacted = SECRET_PATTERN.sub(r"\1=[REDACTED]", value)
        redacted = re.sub(r"([?&][^=&#\s]+=)[^&#\s]*", r"\1[REDACTED]", redacted)
        clues.append({
            "member": member_name,
            "string_data_offset": string_off,
            "indicators": indicators,
            "value_redacted": redacted[:500],
            "validation": "string-pool lead only; locate callers and data flow in decompiled code",
        })
        if len(clues) >= 250:
            return clues, string_count, True
    return clues, string_count, False


def _safe_member_name(name: str) -> bool:
    if "\x00" in name or "\\" in name:
        return False
    path = PurePosixPath(name)
    return not path.is_absolute() and all(part not in {"..", ""} for part in path.parts)


def _elf_header(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> dict | None:
    try:
        with archive.open(info) as stream:
            header = stream.read(20)
    except (OSError, RuntimeError, zipfile.BadZipFile):
        return None
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return None
    byte_order = "little" if header[5] == 1 else "big" if header[5] == 2 else None
    machine = int.from_bytes(header[18:20], byte_order) if byte_order else None
    return {
        "class": {1: "ELF32", 2: "ELF64"}.get(header[4], "unknown"),
        "endianness": "little" if header[5] == 1 else "big" if header[5] == 2 else "unknown",
        "machine": ELF_MACHINES.get(machine, f"unknown-{machine}" if machine is not None else "unknown"),
        "abi_path_hint": info.filename.split("/")[1] if info.filename.startswith("lib/") and "/" in info.filename[4:] else None,
    }


def _which(*names: str) -> str | None:
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return None


def _tool_command(name: str) -> list[str] | None:
    direct = _which(name, name + ".exe")
    if direct and Path(direct).suffix.lower() in {".bat", ".cmd"}:
        direct = None
    if direct:
        return [direct]
    batch = _which(name + ".bat", name + ".cmd")
    java = _which("java", "java.exe")
    if not batch or not java:
        return None
    wrapper = Path(batch).resolve()
    lib_dir = wrapper.parent.parent / "lib"
    jars = [wrapper.parent / f"{name}.jar", wrapper.parent / "lib" / f"{name}.jar",
            lib_dir / f"{name}.jar"]
    if name == "jadx":
        jars.extend(sorted(lib_dir.glob("jadx-cli*.jar")) if lib_dir.is_dir() else [])
    jar = next((candidate for candidate in jars if candidate.is_file()), None)
    if not jar:
        return None
    if name == "jadx":
        return [java, "-cp", str(lib_dir / "*"), "jadx.cli.JadxCLI"]
    if name == "apkanalyzer":
        return [java, f"-Dcom.android.sdklib.toolsdir={wrapper.parent.parent}",
                "-cp", str(lib_dir / "*"), "com.android.tools.apk.analyzer.ApkAnalyzerCli"]
    return [java, "-jar", str(jar)]


def _run_tool(executable: str | list[str], args: list[str], timeout: int = 60) -> dict:
    try:
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            command = [executable] if isinstance(executable, str) else executable
            result = subprocess.run([*command, *args], stdout=stdout_file,
                                    stderr=stderr_file, timeout=timeout,
                                    check=False, shell=False)
            stdout_file.seek(0, 2)
            stdout_size = stdout_file.tell()
            stderr_file.seek(0, 2)
            stderr_size = stderr_file.tell()
            stdout_file.seek(0)
            stdout = stdout_file.read(MAX_TOOL_OUTPUT_BYTES + 1)
            stderr_file.seek(max(0, stderr_size - 8000))
            stderr = stderr_file.read(8000)
        return {
            "exit_code": result.returncode,
            "stdout": stdout[:MAX_TOOL_OUTPUT_BYTES].decode("utf-8", "replace"),
            "stderr": stderr.decode("utf-8", "replace"),
            "output_truncated": stdout_size > MAX_TOOL_OUTPUT_BYTES,
        }
    except subprocess.TimeoutExpired:
        return {"error": f"timed out after {timeout} seconds"}
    except OSError as exc:
        return {"error": f"could not start tool: {exc.__class__.__name__}"}


def _scan_decompiled_tree(root: Path) -> dict:
    hits = []
    files_seen = 0
    bytes_seen = 0
    truncated = False
    for source in root.rglob("*"):
        if not source.is_file() or source.suffix.lower() not in {".java", ".kt", ".smali"}:
            continue
        files_seen += 1
        if files_seen > MAX_DECOMPILED_FILES:
            truncated = True
            break
        try:
            size = source.stat().st_size
            if size > 16 * 1024 * 1024:
                truncated = True
                continue
            if bytes_seen + size > MAX_DECOMPILED_SOURCE_BYTES:
                truncated = True
                break
            bytes_seen += size
            with source.open("r", encoding="utf-8", errors="replace") as stream:
                line_number = 0
                while True:
                    line = stream.readline(65_536)
                    if not line:
                        break
                    line_number += 1
                    for rule_id, area, pattern, rationale in CODE_RULES:
                        match = pattern.search(line)
                        if not match:
                            continue
                        excerpt = SECRET_PATTERN.sub(r"\1=[REDACTED]", line.strip())
                        excerpt = re.sub(r"([?&][^=&#\s]+=)[^&#\s]*", r"\1[REDACTED]", excerpt)
                        hits.append({
                            "rule_id": rule_id,
                            "masvs_area": MASVS_AREAS.get(area, f"MASVS-{area.upper()}"),
                            "file": str(source.relative_to(root)).replace("\\", "/"),
                            "line": line_number,
                            "evidence_excerpt_redacted": excerpt[:500],
                            "interpretation": rationale,
                            "status": "static-candidate-requires-call-path-validation",
                        })
                        if len(hits) >= MAX_CODE_FINDINGS:
                            truncated = True
                            break
                    if len(hits) >= MAX_CODE_FINDINGS:
                        break
        except OSError:
            continue
        if len(hits) >= MAX_CODE_FINDINGS:
            break
    return {"files_scanned": min(files_seen, MAX_DECOMPILED_FILES),
            "source_bytes_scanned": bytes_seen, "findings": hits,
            "finding_count": len(hits), "truncated": truncated,
            "coverage_note": "Line-level pattern matches are leads; confirm syntax, reachability, platform guards, and data flow."}


def _decompile_with_jadx(apk: Path) -> dict:
    executable = _tool_command("jadx")
    if not executable:
        return {"status": "unavailable", "tool": "jadx"}
    version = _run_tool(executable, ["--version"], timeout=20)
    try:
        with tempfile.TemporaryDirectory(prefix="qnx-jadx-") as temp_dir:
            output_dir = Path(temp_dir) / "src"
            result = _run_tool(executable, ["-d", str(output_dir), str(apk)], timeout=300)
            if result.get("exit_code") != 0 or not output_dir.is_dir():
                return {"status": "failed", "version": version.get("stdout", "").strip(),
                        "run": result}
            return {"status": "completed", "version": version.get("stdout", "").strip(),
                    "run": {key: val for key, val in result.items() if key != "stdout"},
                    **_scan_decompiled_tree(output_dir)}
    except OSError as exc:
        return {"status": "failed", "error": exc.__class__.__name__}


def _decode_with_apktool(apk: Path) -> dict:
    executable = _tool_command("apktool")
    if not executable:
        return {"status": "unavailable", "tool": "apktool"}
    version = _run_tool(executable, ["--version"], timeout=20)
    try:
        with tempfile.TemporaryDirectory(prefix="qnx-apktool-") as temp_dir:
            output_dir = Path(temp_dir) / "decoded"
            result = _run_tool(executable, ["d", "-f", "-o", str(output_dir), str(apk)], timeout=300)
            manifest_facts = None
            manifest_file = output_dir / "AndroidManifest.xml"
            if manifest_file.is_file() and manifest_file.stat().st_size <= 8 * 1024 * 1024:
                try:
                    manifest_facts = _manifest_facts(manifest_file.read_text(encoding="utf-8", errors="replace"))
                except (ET.ParseError, OSError):
                    pass
            source_scan = _scan_decompiled_tree(output_dir) if result.get("exit_code") == 0 else None
            return {"status": "completed" if result.get("exit_code") == 0 else "failed",
                    "version": version.get("stdout", "").strip(),
                    "run": {key: val for key, val in result.items() if key != "stdout"},
                    "manifest": manifest_facts, "smali_analysis": source_scan}
    except OSError as exc:
        return {"status": "failed", "error": exc.__class__.__name__}


def _dependency_inventory(apk: Path, max_components: int = 500,
                           scan_vulnerabilities: bool = False) -> dict:
    components = {}
    hints = []
    try:
        with zipfile.ZipFile(apk) as archive:
            for info in archive.infolist():
                name = info.filename
                lower = name.lower()
                if lower.endswith("/pom.properties") and "/meta-inf/maven/" in lower and info.file_size <= 64 * 1024:
                    try:
                        with archive.open(info) as stream:
                            raw_bytes = stream.read(64 * 1024 + 1)
                        if len(raw_bytes) > 64 * 1024:
                            continue
                        raw = raw_bytes.decode("utf-8", "replace")
                    except (OSError, RuntimeError, zipfile.BadZipFile):
                        continue
                    props = {}
                    for line in raw.splitlines():
                        line = line.strip()
                        if line and not line.startswith(("#", "!")) and "=" in line:
                            key, value = line.split("=", 1)
                            props[key.strip()] = value.strip()
                    group, artifact, version = (props.get("groupId"), props.get("artifactId"), props.get("version"))
                    if group and artifact and version:
                        purl = f"pkg:maven/{quote(group, safe='.-_')}/{quote(artifact, safe='.-_')}@{quote(version, safe='.-_+~')}"
                        components[purl] = {"type": "library", "name": f"{group}:{artifact}",
                                            "version": version, "purl": purl,
                                            "evidence": name, "confidence": "embedded Maven pom.properties"}
                elif lower.endswith((".jar", ".aar")) or lower.startswith(("lib/", "assets/")) and "license" in lower:
                    hints.append(name[:512])
                if len(components) >= max_components:
                    break
    except (OSError, zipfile.BadZipFile):
        return {"error": "dependency inventory unavailable", "components": [], "component_count": 0}
    items = sorted(components.values(), key=lambda item: item["purl"])
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"tools": [{"vendor": "Qi-NX", "name": "QNX-Agent Android APK engine"}]},
            "components": items}
    osv = {"status": "not-requested", "reason": "network-capable advisory lookup requires explicit opt-in"}
    scanner = _which("osv-scanner", "osv-scanner.exe")
    if scan_vulnerabilities and not items:
        osv = {"status": "not-run", "reason": "no exact-version Maven components found"}
    elif scan_vulnerabilities and scanner:
        try:
            with tempfile.TemporaryDirectory(prefix="qnx-apk-sbom-") as temp_dir:
                sbom_path = Path(temp_dir) / "bom.cdx.json"
                sbom_path.write_text(json.dumps(sbom, ensure_ascii=False), encoding="utf-8")
                result = _run_tool(scanner, ["scan", "source", "-L", str(sbom_path), "--format", "json"], timeout=180)
                osv = {"status": "completed" if result.get("exit_code") == 0 else "failed",
                       "exit_code": result.get("exit_code"), "output_truncated": result.get("output_truncated"),
                       "report": result.get("stdout", ""), "stderr": result.get("stderr", "")}
        except OSError as exc:
            osv = {"status": "failed", "error": exc.__class__.__name__}
    elif scan_vulnerabilities and not scanner:
        osv = {"status": "unavailable", "reason": "osv-scanner not found"}
    return {"components": items, "component_count": len(items),
            "unversioned_dependency_hints": hints[:100], "hints_truncated": len(hints) > 100,
            "sbom": sbom, "osv_scan": osv,
            "coverage_note": "Only embedded Maven pom.properties provide exact coordinates here; shaded, native, obfuscated, and metadata-free libraries can be missed. OSV results are version matches, not proof of reachable vulnerable code."}


def _osv_findings(report_text: str) -> list[dict]:
    try:
        report = json.loads(report_text)
    except (TypeError, json.JSONDecodeError):
        return []
    findings = []
    for result in report.get("results", []) or []:
        for package_row in result.get("packages", []) or []:
            package = package_row.get("package", {})
            name, version, ecosystem = (package.get("name"), package.get("version"), package.get("ecosystem"))
            for vuln in package_row.get("vulnerabilities", []) or []:
                score = None
                for item in vuln.get("severity", []) or []:
                    raw_score = item.get("score")
                    try:
                        candidate_score = float(raw_score)
                        if 0 <= candidate_score <= 10:
                            score = max(score or 0, candidate_score)
                    except (TypeError, ValueError):
                        pass
                level = ("CRITICAL" if score >= 9 else "HIGH" if score >= 7 else
                         "MEDIUM" if score >= 4 else "LOW" if score is not None else "UNRATED")
                aliases = vuln.get("aliases", [])
                fixed = []
                for affected in vuln.get("affected", []) or []:
                    for item in affected.get("ranges", []) or []:
                        fixed.extend(event["fixed"] for event in item.get("events", []) if event.get("fixed"))
                references = [ref.get("url") for ref in vuln.get("references", []) or [] if ref.get("url")]
                identifier = vuln.get("id", "unknown-advisory")
                _candidate(findings, "dependency-vulnerability", level,
                           f"Dependency advisory match: {identifier}",
                           "OSV matched the embedded package name/version to an advisory. Confirm package identity, affected range, shaded/repackaged status, reachable vulnerable code, and vendor backports before assigning impact.",
                           f"{ecosystem}:{name}@{version}; source={result.get('source', {}).get('path', 'SBOM')}")
                findings[-1].update({
                    "masvs_area": "MASVS-CODE",
                    "status": "unverified-version-match",
                    "confidence": "database/version match only; vulnerable code reachability not assessed",
                    "advisory_id": identifier,
                    "aliases": aliases,
                    "cvss_score": score,
                    "fixed_versions": sorted(set(fixed)),
                    "references": references,
                })
    return findings


def _manifest_facts(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    app = root.find("application")
    permissions = []
    for element in root:
        if element.tag in {"uses-permission", "uses-permission-sdk-23",
                            "uses-permission-sdk-m"}:
            permissions.append({
                "name": element.get(ANDROID_NS + "name"),
                "max_sdk_version": element.get(ANDROID_NS + "maxSdkVersion"),
            })
    components = []
    if app is not None:
        for element in app:
            if element.tag not in COMPONENT_TAGS:
                continue
            intent_filters = sum(1 for child in element if child.tag == "intent-filter")
            components.append({
                "type": element.tag,
                "name": element.get(ANDROID_NS + "name"),
                "exported": element.get(ANDROID_NS + "exported"),
                "permission": element.get(ANDROID_NS + "permission"),
                "intent_filter_count": intent_filters,
                "read_permission": element.get(ANDROID_NS + "readPermission"),
                "write_permission": element.get(ANDROID_NS + "writePermission"),
                "authorities": element.get(ANDROID_NS + "authorities"),
            })
    uses_sdk = root.find("uses-sdk")
    application_attrs = {}
    if app is not None:
        for key in ("debuggable", "allowBackup", "fullBackupContent",
                    "dataExtractionRules", "usesCleartextTraffic",
                    "networkSecurityConfig", "testOnly", "permission"):
            value = app.get(ANDROID_NS + key)
            if value is not None:
                application_attrs[key] = value
    return {
        "package": root.get("package"),
        "version_code": root.get(ANDROID_NS + "versionCode"),
        "version_name": root.get(ANDROID_NS + "versionName"),
        "install_location": root.get(ANDROID_NS + "installLocation"),
        "min_sdk": uses_sdk.get(ANDROID_NS + "minSdkVersion") if uses_sdk is not None else None,
        "target_sdk": uses_sdk.get(ANDROID_NS + "targetSdkVersion") if uses_sdk is not None else None,
        "permissions": permissions,
        "components": components,
        "application_attributes": application_attrs,
    }


def _aapt_facts(tree_text: str) -> dict:
    """Recover common manifest fields from Android aapt/aapt2 xmltree output."""
    stack: list[dict] = []
    root: dict | None = None
    for line in tree_text.splitlines():
        match = re.match(r"^(\s*)E: ([^\s(]+)", line)
        if match:
            depth = len(match.group(1))
            element = {"tag": match.group(2), "attrs": {}, "children": [], "_depth": depth}
            while stack and stack[-1]["_depth"] >= depth:
                stack.pop()
            if stack:
                stack[-1]["children"].append(element)
            else:
                root = element
            stack.append(element)
            continue
        attr = re.match(r"^\s*A: ([^=]+)=(.*)$", line)
        if not attr or not stack:
            continue
        key = re.sub(r"\([^)]*\)$", "", attr.group(1).strip())
        raw = attr.group(2).strip()
        quoted = re.match(r'^"([^"]*)"', raw)
        if quoted:
            value = quoted.group(1)
        elif "0xffffffff" in raw.lower():
            value = "true"
        elif "0x00000000" in raw.lower():
            value = "false"
        else:
            value_match = re.search(r"0x([0-9a-fA-F]+)$", raw)
            value = str(int(value_match.group(1), 16)) if value_match else raw
        stack[-1]["attrs"][key] = value
    if root is None or root["tag"] != "manifest":
        raise ValueError("aapt output did not contain a manifest root")

    def value(element: dict | None, name: str):
        return element["attrs"].get(name) if element else None

    def first_child(element: dict, name: str) -> dict | None:
        return next((child for child in element["children"] if child["tag"] == name), None)

    app = first_child(root, "application")
    sdk = first_child(root, "uses-sdk")
    permissions = []
    for element in root["children"]:
        if element["tag"] in {"uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"}:
            permissions.append({"name": value(element, "android:name"),
                                "max_sdk_version": value(element, "android:maxSdkVersion")})
    components = []
    if app:
        for element in app["children"]:
            if element["tag"] not in COMPONENT_TAGS:
                continue
            components.append({
                "type": element["tag"],
                "name": value(element, "android:name"),
                "exported": value(element, "android:exported"),
                "permission": value(element, "android:permission"),
                "intent_filter_count": sum(1 for child in element["children"]
                                            if child["tag"] == "intent-filter"),
                "read_permission": value(element, "android:readPermission"),
                "write_permission": value(element, "android:writePermission"),
                "authorities": value(element, "android:authorities"),
            })
    app_attrs = {}
    if app:
        for name in ("debuggable", "allowBackup", "fullBackupContent",
                     "dataExtractionRules", "usesCleartextTraffic",
                     "networkSecurityConfig", "testOnly", "permission"):
            key = "android:" + name
            if key in app["attrs"]:
                app_attrs[name] = app["attrs"][key]
    return {
        "package": value(root, "package"),
        "version_code": value(root, "android:versionCode"),
        "version_name": value(root, "android:versionName"),
        "install_location": value(root, "android:installLocation"),
        "min_sdk": value(sdk, "android:minSdkVersion"),
        "target_sdk": value(sdk, "android:targetSdkVersion"),
        "permissions": permissions,
        "components": components,
        "application_attributes": app_attrs,
    }


def _candidate(findings: list[dict], category: str, severity: str,
               title: str, detail: str, evidence: str,
               mastg_refs: list[dict] | None = None) -> None:
    number = len(findings) + 1
    findings.append({
        "finding_id": f"F-{number:04d}",
        "evidence_id": f"E-{number:04d}",
        "category": category,
        "severity": severity,
        "masvs_area": MASVS_AREAS.get(category, "MASVS-OTHER"),
        "mastg_references": mastg_refs or [],
        "status": "unverified-static-lead",
        "confidence": "candidate; requires code-path or runtime validation",
        "title": title,
        "detail": detail,
        "remediation": REMEDIATION_HINTS.get(category, "先验证代码路径与实际影响，再按最小权限和安全默认值修复。"),
        "evidence": evidence,
    })


def _audit_manifest(facts: dict, members: list[dict]) -> list[dict]:
    findings: list[dict] = []
    attrs = facts["application_attributes"]
    if attrs.get("debuggable", "").lower() == "true":
        _candidate(findings, "application-configuration", "MEDIUM",
                   "Application debuggable flag is enabled",
                   "Debuggable builds may expose debugging surfaces; confirm build intent and release status.",
                   "AndroidManifest.xml application android:debuggable=true",
                   MASTG_REFERENCES["android-debuggable"])
    if attrs.get("usesCleartextTraffic", "").lower() == "true":
        _candidate(findings, "transport-security", "MEDIUM",
                   "Manifest permits cleartext traffic",
                   "Determine whether sensitive traffic can use cleartext and whether Network Security Config narrows this setting.",
                   "AndroidManifest.xml application android:usesCleartextTraffic=true",
                   MASTG_REFERENCES["android-cleartext"])
    if attrs.get("allowBackup", "").lower() == "true":
        _candidate(findings, "data-protection", "LOW",
                   "Application backup is enabled",
                   "Review backup rules, Android version behavior, and whether sensitive app data is excluded.",
                   "AndroidManifest.xml application android:allowBackup=true",
                   MASTG_REFERENCES["android-backup"])
    if attrs.get("testOnly", "").lower() == "true":
        _candidate(findings, "application-configuration", "LOW",
                   "Application is marked test-only",
                   "Confirm whether this is an expected test artifact or an unintended release configuration.",
                   "AndroidManifest.xml application android:testOnly=true")
    for component in facts["components"]:
        if component["exported"] == "true" and not component["permission"]:
            _candidate(findings, "component-exposure", "MEDIUM",
                       "Exported component has no manifest permission",
                       "Export alone is not a vulnerability; inspect the component's inputs, authorization checks, and sensitive operations.",
                       f"{component['type']} {component['name']} exported=true; no android:permission")
        elif component["exported"] is None and component["intent_filter_count"]:
            _candidate(findings, "component-exposure", "INFO",
                       "Component export behavior depends on platform/build rules",
                       "Resolve merged-manifest defaults against targetSdk and Android API level; do not infer reachability from this row alone.",
                       f"{component['type']} {component['name']} has intent filters and no explicit android:exported")
    nested_apks = [item["name"] for item in members if item["name"].lower().endswith(".apk")]
    if nested_apks:
        _candidate(findings, "package-coverage", "INFO",
                   "Container includes nested APK members",
                   "Nested split/package members are inventoried but not independently parsed by this first-pass analyzer.",
                   ", ".join(nested_apks[:20]))
    return findings


def analyze(target: str, *, max_entries: int = 20_000, deep_analysis: bool = False,
            isolated_tooling_confirmed: bool = False,
            scan_vulnerabilities: bool = False) -> dict:
    path = Path(target).expanduser().resolve()
    if not path.is_file():
        return {"error": f"target is not a regular file: {path}", "author": BANNER}
    if path.stat().st_size > MAX_APK_BYTES:
        return {"error": f"input exceeds {MAX_APK_BYTES} byte limit", "author": BANNER}
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    sha256 = digest.hexdigest()
    if not zipfile.is_zipfile(path):
        return {"error": "input is not a readable ZIP-based Android package", "target": str(path),
                "sha256": sha256, "author": BANNER}

    findings: list[dict] = []
    members: list[dict] = []
    unsafe_members: list[str] = []
    dex_clues: list[dict] = []
    dex_string_counts: dict[str, int] = {}
    dex_scan_truncated = False
    tool_results: dict = {}
    manifest_facts = None
    archive_warnings: list[str] = []
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_ENTRIES:
                return {"error": f"archive contains more than {MAX_ARCHIVE_ENTRIES} entries",
                        "target": str(path), "sha256": sha256, "author": BANNER}
            expanded_total = sum(info.file_size for info in infos)
            if expanded_total > MAX_EXPANDED_BYTES:
                archive_warnings.append("Declared expanded size exceeds analysis cap; member hashing skipped.")
            total_hashed = 0
            member_hashable = expanded_total <= MAX_EXPANDED_BYTES
            selected_infos = infos[:max(1, min(int(max_entries), MAX_ARCHIVE_ENTRIES))]
            for info in selected_infos:
                if info.is_dir():
                    continue
                safe = _safe_member_name(info.filename)
                if not safe:
                    unsafe_members.append(info.filename[:512])
                ratio = (info.file_size / info.compress_size) if info.compress_size else None
                kind = "other"
                lower = info.filename.lower()
                if lower == "androidmanifest.xml":
                    kind = "manifest"
                elif lower.endswith(".dex"):
                    kind = "dex"
                elif lower.endswith(".so") and lower.startswith("lib/"):
                    kind = "native-library"
                elif lower.endswith(".apk"):
                    kind = "nested-apk"
                elif lower.startswith("meta-inf/"):
                    kind = "signature-or-metadata"
                elif lower == "resources.arsc":
                    kind = "resources"
                item = {
                    "name": info.filename[:1024],
                    "kind": kind,
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                    "compression_ratio": round(ratio, 2) if ratio is not None else None,
                    "crc32": f"{info.CRC:08x}",
                    "sha256": None,
                }
                if kind == "native-library":
                    item["elf"] = _elf_header(archive, info)
                if ratio is not None and ratio > 1000:
                    archive_warnings.append(f"High compression ratio for {info.filename[:160]}.")
                can_hash = (member_hashable and safe and info.file_size <= MAX_MEMBER_HASH_BYTES
                            and total_hashed + info.file_size <= MAX_TOTAL_MEMBER_HASH_BYTES
                            and kind != "other")
                if can_hash:
                    if kind == "dex":
                        with archive.open(info) as member_stream:
                            dex_data = member_stream.read(MAX_MEMBER_HASH_BYTES + 1)
                        if len(dex_data) <= MAX_MEMBER_HASH_BYTES:
                            item["sha256"] = hashlib.sha256(dex_data).hexdigest()
                            total_hashed += len(dex_data)
                            if len(dex_data) <= MAX_DEX_SCAN_BYTES:
                                if len(dex_string_counts) < MAX_DEX_FILES_SCANNED:
                                    found, string_count, was_truncated = _dex_clues(dex_data, info.filename)
                                    remaining = max(0, 250 - len(dex_clues))
                                    dex_clues.extend(found[:remaining])
                                    dex_string_counts[info.filename] = string_count
                                    dex_scan_truncated = dex_scan_truncated or was_truncated or len(found) > remaining
                                else:
                                    archive_warnings.append("DEX scan file-count cap reached.")
                                    dex_scan_truncated = True
                            else:
                                archive_warnings.append(f"DEX string scan skipped above {MAX_DEX_SCAN_BYTES} bytes: {info.filename[:160]}.")
                                dex_scan_truncated = True
                    else:
                        with archive.open(info) as member_stream:
                            item["sha256"], bytes_read = _sha256_stream(
                                member_stream, MAX_MEMBER_HASH_BYTES)
                        if item["sha256"]:
                            total_hashed += bytes_read
                elif kind == "dex":
                    archive_warnings.append(f"DEX hashing/string scan skipped by size or work limit: {info.filename[:160]}.")
                    dex_scan_truncated = True
                if kind == "manifest" and safe and info.file_size <= 8 * 1024 * 1024:
                    with archive.open(info) as member_stream:
                        manifest_bytes = member_stream.read(8 * 1024 * 1024 + 1)
                    if manifest_bytes.startswith(b"<?xml") or manifest_bytes.lstrip().startswith(b"<manifest"):
                        try:
                            manifest_facts = _manifest_facts(manifest_bytes.decode("utf-8", "replace"))
                            tool_results["manifest_source"] = "plain-xml-in-archive"
                        except ET.ParseError as exc:
                            archive_warnings.append(f"Plain XML manifest parse failed: {exc}")
                members.append(item)
            truncated = len(infos) > len(selected_infos)
            if unsafe_members:
                _candidate(findings, "archive-integrity", "HIGH",
                           "Archive contains unsafe member paths",
                           "Path traversal or platform-specific path syntax can be dangerous to downstream extractors; this analyzer did not extract members.",
                           ", ".join(unsafe_members[:20]))
    except (OSError, zipfile.BadZipFile, RuntimeError, ValueError) as exc:
        return {"error": f"could not inspect archive: {exc.__class__.__name__}",
                "target": str(path), "sha256": sha256, "author": BANNER}

    is_single_apk = path.suffix.lower() == ".apk"
    if is_single_apk and isolated_tooling_confirmed:
        tool_results["external_android_tools"] = {"status": "enabled", "isolation_confirmed": True}
    else:
        tool_results["external_android_tools"] = {
            "status": "skipped",
            "reason": "set isolated_tooling_confirmed=true before running external tools against a sample",
        }
    apkanalyzer = _tool_command("apkanalyzer") if isolated_tooling_confirmed else None
    if apkanalyzer and is_single_apk:
        summary = _run_tool(apkanalyzer, ["apk", "summary", str(path)])
        tool_results["apkanalyzer_summary"] = summary
        tool_results["apkanalyzer_dex_list"] = _run_tool(
            apkanalyzer, ["dex", "list", str(path)])
        tool_results["apkanalyzer_dex_references"] = _run_tool(
            apkanalyzer, ["dex", "references", str(path)])
        tool_results["apkanalyzer_dex_packages"] = _run_tool(
            apkanalyzer, ["dex", "packages", "--defined-only", str(path)])
        manifest_output = _run_tool(apkanalyzer, ["manifest", "print", str(path)])
        tool_results["apkanalyzer_manifest"] = {
            key: value for key, value in manifest_output.items() if key != "stdout"
        }
        if "stdout" in manifest_output:
            tool_results["apkanalyzer_manifest"]["stdout"] = manifest_output["stdout"]
            try:
                manifest_facts = _manifest_facts(manifest_output["stdout"])
                tool_results["manifest_source"] = "apkanalyzer"
            except ET.ParseError as exc:
                tool_results["manifest_parse_error"] = str(exc)
    if manifest_facts is None and is_single_apk and isolated_tooling_confirmed:
        aapt2 = _which("aapt2", "aapt2.exe")
        if aapt2:
            decoded = _run_tool(aapt2, ["dump", "xmltree", str(path), "--file", "AndroidManifest.xml"])
            tool_results["aapt2_manifest"] = {key: val for key, val in decoded.items() if key != "stdout"}
            if decoded.get("stdout"):
                try:
                    manifest_facts = _aapt_facts(decoded["stdout"])
                    tool_results["manifest_source"] = "aapt2"
                except ValueError as exc:
                    tool_results["manifest_parse_error"] = str(exc)
        else:
            aapt = _which("aapt", "aapt.exe")
            if aapt:
                decoded = _run_tool(aapt, ["dump", "xmltree", str(path), "AndroidManifest.xml"])
                tool_results["aapt_manifest"] = {key: val for key, val in decoded.items() if key != "stdout"}
                if decoded.get("stdout"):
                    try:
                        manifest_facts = _aapt_facts(decoded["stdout"])
                        tool_results["manifest_source"] = "aapt"
                    except ValueError as exc:
                        tool_results["manifest_parse_error"] = str(exc)
    if manifest_facts is None and is_single_apk and isolated_tooling_confirmed:
        aapt = _which("aapt2", "aapt2.exe", "aapt", "aapt.exe")
        if aapt:
            tool_results["aapt_badging"] = _run_tool(aapt, ["dump", "badging", str(path)])

    apksigner = _tool_command("apksigner") if isolated_tooling_confirmed else None
    if apksigner and is_single_apk:
        tool_results["apksigner_verify"] = _run_tool(
            apksigner, ["verify", "--verbose", "--print-certs", str(path)])
    elif not is_single_apk:
        tool_results["apksigner_verify"] = {
            "status": "skipped",
            "reason": "Signer verification is run per APK; this container may include nested APK splits.",
        }
    else:
        tool_results["apksigner_verify"] = {
            "status": "unavailable" if isolated_tooling_confirmed else "skipped",
            "reason": "apksigner not found" if isolated_tooling_confirmed else "external sample parsers were not enabled",
        }

    if path.suffix.lower() == ".aab":
        archive_warnings.append("AAB module manifests are not decoded by this first-pass APK analyzer; use bundletool to build a device-specific APK set for per-APK analysis.")
    elif any(item["kind"] == "nested-apk" for item in members):
        archive_warnings.append("Nested APK split members are inventoried, not independently decoded; analyze each APK split to establish full coverage.")

    if manifest_facts is not None:
        findings.extend(_audit_manifest(manifest_facts, members))
        app_attrs = manifest_facts["application_attributes"]
        if app_attrs.get("networkSecurityConfig"):
            archive_warnings.append("Referenced Network Security Config XML is not decoded by this first-pass engine; review the resource separately.")
        if app_attrs.get("fullBackupContent") or app_attrs.get("dataExtractionRules"):
            archive_warnings.append("Referenced backup/data-extraction rules are not decoded by this first-pass engine.")
    else:
        archive_warnings.append("AndroidManifest.xml was not decoded; component and configuration checks are incomplete.")
    signer = tool_results.get("apksigner_verify") or {}
    if signer.get("exit_code") not in (None, 0):
        _candidate(findings, "signing-integrity", "HIGH",
                   "APK signature verification failed",
                   "The APK signature could not be verified by the available apksigner; distinguish unsigned, malformed, unsupported, or modified artifacts.",
                   f"apksigner exit code {signer.get('exit_code')}; review its output and compare against a trusted release certificate.")

    dependency_analysis = _dependency_inventory(path, scan_vulnerabilities=scan_vulnerabilities)
    osv = dependency_analysis.get("osv_scan") or {}
    if osv.get("status") == "completed":
        findings.extend(_osv_findings(osv.get("report", "")))
    code_analysis = {"jadx": {"status": "skipped", "reason": "deep analysis not requested"},
                     "apktool": {"status": "skipped", "reason": "deep analysis not requested"}}
    if is_single_apk and deep_analysis and not isolated_tooling_confirmed:
        code_analysis = {"jadx": {"status": "blocked", "reason": "confirm an isolated analyst environment before parsing hostile APKs"},
                         "apktool": {"status": "blocked", "reason": "confirm an isolated analyst environment before parsing hostile APKs"}}
    elif is_single_apk and deep_analysis and isolated_tooling_confirmed:
        code_analysis = {"jadx": _decompile_with_jadx(path),
                         "apktool": _decode_with_apktool(path)}
        if manifest_facts is None and code_analysis["apktool"].get("manifest"):
            manifest_facts = code_analysis["apktool"]["manifest"]
            findings.extend(_audit_manifest(manifest_facts, members))
            archive_warnings = [warning for warning in archive_warnings
                                if warning != "AndroidManifest.xml was not decoded; component and configuration checks are incomplete."]
        for engine_name in ("jadx", "apktool"):
            result = code_analysis[engine_name]
            hits = result.get("findings", []) or (result.get("smali_analysis") or {}).get("findings", [])
            for hit in hits:
                _candidate(findings, hit["rule_id"], "UNRATED",
                           f"Android code pattern: {hit['rule_id']}", hit["interpretation"],
                           f"{engine_name}:{hit['file']}:{hit['line']} {hit['evidence_excerpt_redacted']}")
                findings[-1]["masvs_area"] = hit["masvs_area"]
                findings[-1]["rule_id"] = hit["rule_id"]
                findings[-1]["mastg_references"] = MASTG_REFERENCES.get(hit["rule_id"], [])
        for component in dependency_analysis.get("components", []):
            component.setdefault("vulnerability_match_status", "not-scanned")
    for finding in findings:
        finding.setdefault("masvs_area", MASVS_AREAS.get(finding.get("category"), "MASVS-OTHER"))

    severity_order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNRATED")
    severity_counts = {level: sum(1 for finding in findings if finding["severity"] == level)
                       for level in severity_order}
    max_severity = next((level for level in severity_order if severity_counts[level]), None)

    return {
        "analysis": "static-deep" if any(item.get("status") == "completed" for item in code_analysis.values()) else "static-first-pass",
        "target": str(path),
        "file_name": path.name,
        "file_size": path.stat().st_size,
        "package_container": path.suffix.lower().lstrip("."),
        "sha256": sha256,
        "archive": {
            "entry_count": len(infos),
            "file_count_included": len(members),
            "expanded_bytes_declared": expanded_total,
            "entries_truncated": truncated,
            "unsafe_member_paths": unsafe_members[:100],
            "warnings": archive_warnings,
            "members": members,
        },
        "dex_analysis": {
            "string_pool_counts": dex_string_counts,
            "string_clues": dex_clues[:250],
            "clue_count": len(dex_clues),
            "truncated_or_skipped": dex_scan_truncated,
            "interpretation": "String matches are investigative leads; they do not establish a call path or vulnerability.",
        },
        "manifest": manifest_facts,
        "signing": tool_results.get("apksigner_verify"),
        "tool_results": tool_results,
        "code_analysis": code_analysis,
        "dependency_analysis": dependency_analysis,
        "findings": findings,
        "finding_count": len(findings),
        "severity_counts": severity_counts,
        "overall_risk": "requires-contextual-review" if findings else "undetermined",
        "scanner_reported_max_severity": max_severity,
        "limitations": [
            "This is a static first-pass audit, not proof of exploitability or a certification that the app is safe.",
            "DEX code, native code, embedded dependency versions, runtime behavior, backend APIs, and omitted split APKs require separate analysis.",
            "Manifest candidates require source/call-path review and platform-version context; tool availability limits are listed above.",
            "The default parser does not extract archive members. If explicitly enabled, JADX/APKTool decode into temporary directories that are removed after analysis; static analysis never installs or executes app code.",
        ],
        "author": BANNER,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect an Android package and audit its manifest without installing it.")
    parser.add_argument("target", help="APK, APKS, XAPK, APKM, or AAB file")
    parser.add_argument("--max-entries", type=int, default=20_000)
    parser.add_argument("--deep", action="store_true", help="enable JADX/APKTool parsing (requires --confirm-isolated-tooling)")
    parser.add_argument("--confirm-isolated-tooling", action="store_true",
                        help="confirm external APK parsers run inside an isolated analyst environment")
    parser.add_argument("--scan-vulnerabilities", action="store_true",
                        help="opt in to OSV-Scanner; may contact public advisory services")
    parser.add_argument("--json", action="store_true", help="retained for script-tool compatibility")
    args = parser.parse_args()
    try:
        result = analyze(args.target, max_entries=args.max_entries,
                         deep_analysis=args.deep,
                         isolated_tooling_confirmed=args.confirm_isolated_tooling,
                         scan_vulnerabilities=args.scan_vulnerabilities)
    except Exception as exc:  # noqa: BLE001
        result = {"error": f"analysis failed: {exc.__class__.__name__}", "author": BANNER}
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    return 0 if "error" not in result else 2


if __name__ == "__main__":
    raise SystemExit(main())
