#!/usr/bin/env python3
"""Normalize common vulnerability-scanner JSON into an evidence-led assessment.

Supported formats: Trivy JSON, OSV-Scanner v2 JSON, Semgrep JSON, and SARIF 2.x.
This module only parses reports; it does not scan, execute, or modify the target.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

BANNER = "by QNX-Agent (Copyright Qi-NX)"
MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_FINDINGS = 1_000
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")


def _text(value, limit: int = 4000) -> str | None:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, default=str)
    return str(value)[:limit]


def _severity(value) -> str:
    text = str(value or "").upper()
    try:
        score = float(text)
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0:
            return "LOW"
    except ValueError:
        pass
    if text in {"CRITICAL", "SEVERE"}:
        return "CRITICAL"
    if text in {"HIGH", "ERROR"}:
        return "HIGH"
    if text in {"MEDIUM", "MODERATE", "WARNING"}:
        return "MEDIUM"
    if text in {"LOW", "NOTE"}:
        return "LOW"
    if text in {"INFO", "INFORMATIONAL"}:
        return "INFO"
    return "UNKNOWN"


def _finding(kind: str, identifier, title, severity, *, package=None,
             version=None, fixed=None, ecosystem=None, purl=None,
             cwe=None, path=None, line=None, url=None,
             description=None, rule=None, cvss=None, remediation=None,
             aliases=None) -> dict:
    return {
        "kind": kind,
        "id": _text(identifier or rule or "scanner-finding", 256),
        "aliases": _text(aliases, 1000),
        "title": _text(title or identifier or rule or "Scanner finding", 1000),
        "severity": _severity(severity),
        "package": _text(package, 512),
        "ecosystem": _text(ecosystem, 128),
        "purl": _text(purl, 1024),
        "installed_version": _text(version, 256),
        "fixed_version": _text(fixed, 256),
        "cwe": _text(cwe, 512),
        "path": _text(path, 2048),
        "line": line if isinstance(line, (int, float, str)) else None,
        "rule": _text(rule, 512),
        "cvss": _text(cvss, 512),
        "reference": _text(url, 2048),
        "description": _text(description, 1500),
        "remediation": _text(remediation, 2000),
    }


def _trivy(document: dict) -> list[dict]:
    findings = []
    for result in document.get("Results") or []:
        target = result.get("Target")
        for item in result.get("Vulnerabilities") or []:
            findings.append(_finding(
                "dependency-vulnerability", item.get("VulnerabilityID"),
                item.get("Title"), item.get("Severity"),
                package=item.get("PkgName"), version=item.get("InstalledVersion"),
                purl=((item.get("PkgIdentifier") or {}).get("PURL")),
                fixed=item.get("FixedVersion"), path=target,
                url=item.get("PrimaryURL"), description=item.get("Description"),
                cvss=item.get("CVSS"), remediation=item.get("FixedVersion")))
        for item in result.get("Misconfigurations") or []:
            metadata = item.get("CauseMetadata") or {}
            code = (item.get("Code") or {}).get("Lines") or []
            first_line = code[0].get("Number") if code else None
            findings.append(_finding(
                "misconfiguration", item.get("ID"), item.get("Title"),
                item.get("Severity"), path=metadata.get("Resource") or target,
                line=first_line, description=item.get("Description"),
                remediation=item.get("Resolution")))
        for item in result.get("Secrets") or []:
            findings.append(_finding(
                "secret-exposure", item.get("RuleID"), item.get("Title"),
                item.get("Severity"), path=target, line=item.get("StartLine"),
                description="Potential secret matched by scanner; matched value redacted.",
                rule=item.get("Category")))
    return findings


def _osv(document: dict) -> list[dict]:
    findings = []
    for result in document.get("results") or []:
        source = result.get("source") or {}
        path = source.get("path")
        for package_result in result.get("packages") or []:
            package = package_result.get("package") or {}
            for vuln in package_result.get("vulnerabilities") or []:
                aliases = vuln.get("aliases") or []
                cve = next((alias for alias in aliases if str(alias).upper().startswith("CVE-")), None)
                identifier = cve or vuln.get("id") or (aliases[0] if aliases else None)
                severity = (vuln.get("database_specific") or {}).get("severity")
                if not severity:
                    severity = (vuln.get("ecosystem_specific") or {}).get("severity")
                fixed_versions = []
                for affected in vuln.get("affected") or []:
                    for version_range in affected.get("ranges") or []:
                        fixed_versions.extend(
                            event["fixed"] for event in version_range.get("events") or []
                            if event.get("fixed"))
                references = vuln.get("references") or []
                url = next((ref.get("url") for ref in references if ref.get("url")), None)
                findings.append(_finding(
                    "dependency-vulnerability", identifier, vuln.get("summary"),
                    severity, package=package.get("name"),
                    version=package.get("version"), fixed=", ".join(fixed_versions) or None,
                    ecosystem=package.get("ecosystem"), purl=package.get("purl"),
                    path=path, url=url, description=vuln.get("details"),
                    cvss=vuln.get("severity"), remediation=", ".join(fixed_versions) or None,
                    aliases=aliases))
    return findings


def _semgrep(document: dict) -> list[dict]:
    findings = []
    for result in document.get("results") or []:
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        start = result.get("start") or {}
        fix = extra.get("fix")
        refs = metadata.get("references") or []
        findings.append(_finding(
            "source-code-finding", result.get("check_id"), extra.get("message"),
            extra.get("severity"), path=result.get("path"), line=start.get("line"),
            rule=result.get("check_id"), url=refs[0] if refs else None,
            description=extra.get("message"), remediation=fix,
            cvss=metadata.get("cvss"), cwe=metadata.get("cwe")))
    return findings


def _sarif(document: dict) -> list[dict]:
    findings = []
    for run in document.get("runs") or []:
        rules = {rule.get("id"): rule for rule in
                 ((run.get("tool") or {}).get("driver") or {}).get("rules") or []}
        for result in run.get("results") or []:
            rule_id = result.get("ruleId")
            rule = rules.get(rule_id) or {}
            props = rule.get("properties") or {}
            locations = result.get("locations") or []
            location = ((locations[0] or {}).get("physicalLocation") or {}) if locations else {}
            artifact = location.get("artifactLocation") or {}
            region = location.get("region") or {}
            message = (result.get("message") or {}).get("text")
            findings.append(_finding(
                "source-code-finding", rule_id, (rule.get("shortDescription") or {}).get("text")
                or message, props.get("security-severity") or result.get("level"),
                path=artifact.get("uri"), line=region.get("startLine"), rule=rule_id,
                url=((rule.get("helpUri") or (rule.get("help") or {}).get("markdown"))),
                description=message, remediation=(rule.get("help") or {}).get("text"),
                cvss=props.get("security-severity"),
                cwe=[tag for tag in (props.get("tags") or []) if "cwe" in str(tag).lower()]))
    return findings


def _detect(document: dict, scanner_hint: str | None = None) -> tuple[str, list[dict]]:
    if scanner_hint == "trivy":
        return "trivy", _trivy(document)
    if scanner_hint in {"osv", "osv-scanner"}:
        return "osv-scanner", _osv(document)
    if scanner_hint == "semgrep":
        return "semgrep", _semgrep(document)
    if scanner_hint == "sarif":
        return "sarif", _sarif(document)
    if "SchemaVersion" in document and "Results" in document:
        return "trivy", _trivy(document)
    if isinstance(document.get("runs"), list):
        return "sarif", _sarif(document)
    results = document.get("results")
    if isinstance(results, list) and any("packages" in item for item in results if isinstance(item, dict)):
        return "osv-scanner", _osv(document)
    if isinstance(results, list) and any("check_id" in item or "extra" in item
                                         for item in results if isinstance(item, dict)):
        return "semgrep", _semgrep(document)
    raise ValueError("unsupported scan report: expected Trivy, OSV-Scanner, Semgrep JSON, or SARIF")


def assess_document(document: dict, *, report_sha256: str | None = None,
                    target: str | None = None, target_sha256: str | None = None,
                    scanner: str | None = None) -> dict:
    detected, findings = _detect(document, scanner)
    scanner = scanner or detected
    # Collapse duplicate records from one scanner without hiding different locations.
    unique = {}
    for item in findings:
        key = (item["kind"], item["id"], item["package"], item["path"], item["line"])
        unique.setdefault(key, item)
    all_findings = list(unique.values())
    finding_total = len(all_findings)
    findings = all_findings[:MAX_FINDINGS]
    for index, item in enumerate(findings, 1):
        item["finding_id"] = f"F-{index:04d}"
        item["evidence_id"] = f"E-{index:04d}"
        item["confidence"] = "scanner-reported; applicability requires manual validation"
        item["validation_status"] = "unverified-scanner-lead"

    counts = {severity: sum(1 for item in all_findings if item["severity"] == severity)
              for severity in SEVERITIES}
    ranked = next((severity for severity in SEVERITIES if counts[severity]), None)
    return {
        "assessment": "findings-reported" if findings else "no-findings-reported",
        "overall_risk": "requires-contextual-review" if findings else "undetermined",
        "scanner_reported_max_severity": ranked,
        "scanner": scanner,
        "target": target,
        "target_sha256": target_sha256,
        "report_sha256": report_sha256,
        "finding_count": finding_total,
        "severity_counts": counts,
        "findings_truncated": finding_total > MAX_FINDINGS,
        "findings": findings,
        "limitations": [
            "This assessment summarizes scanner output; it is not proof of exploitability or absence of vulnerabilities.",
            "Validate affected component versions, reachability, configuration, and vendor backports before assigning final risk.",
            "A no-findings result applies only to the scanner, rules/database, target, and coverage recorded in the source report.",
        ],
        "author": BANNER,
    }


def assess_file(source: str, *, target: str | None = None,
                target_sha256: str | None = None, scanner: str | None = None) -> dict:
    path = Path(source)
    if not path.is_file():
        return {"error": f"not a file: {path}"}
    if path.stat().st_size > MAX_REPORT_BYTES:
        return {"error": f"report exceeds {MAX_REPORT_BYTES} byte limit"}
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    document = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(document, dict):
        raise ValueError("scan report JSON root must be an object")
    return assess_document(document, report_sha256=digest, target=target,
                           target_sha256=target_sha256, scanner=scanner)


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize security scanner JSON into an evidence-led assessment.")
    parser.add_argument("report", help="Trivy, OSV-Scanner, Semgrep JSON, or SARIF report")
    parser.add_argument("--target", help="scanned artifact or repository path")
    parser.add_argument("--target-sha256", help="SHA-256 of the scanned artifact, if known")
    parser.add_argument("--scanner", help="scanner name when not inferable")
    parser.add_argument("--json", action="store_true", help="retained for script-tool compatibility")
    args = parser.parse_args()
    try:
        print(json.dumps(assess_file(args.report, target=args.target,
                                     target_sha256=args.target_sha256,
                                     scanner=args.scanner), indent=2, ensure_ascii=False))
        return 0
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"error": str(exc), "author": BANNER}, indent=2, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
