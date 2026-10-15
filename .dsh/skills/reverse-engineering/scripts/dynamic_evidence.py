#!/usr/bin/env python3
"""Normalize exported sandbox / Sysmon / Procmon telemetry into evidence JSON.

This is an offline log parser. It does not start a sandbox or execute a sample.
Supported inputs: CAPE/Cuckoo JSON reports, Sysmon JSONL, and Procmon CSV.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import re
import sys
from collections import Counter
from pathlib import Path

BANNER = "by Qi-NX-Agent (Copyright Qi-NX)"
MAX_INPUT_SIZE = 256 * 1024 * 1024
MAX_EVENTS = 2000
URL_RE = re.compile(r"https?://[^\s\"'<>]{4,512}", re.IGNORECASE)
IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _text(value, limit: int = 2000) -> str:
    try:
        text = json.dumps(value, ensure_ascii=False, default=str) if not isinstance(value, str) else value
    except Exception:
        text = str(value)
    return text[:limit]


def _category(operation: str) -> str:
    value = operation.lower()
    if any(token in value for token in ("dns", "http", "socket", "connect", "send", "recv", "network", "tcp", "udp", "internet")):
        return "network"
    if any(token in value for token in ("registry", "regopen", "regset", "regcreate", "regdelete")):
        return "registry"
    if any(token in value for token in ("file", "createfile", "writefile", "deletefile", "rename", "openat", "unlink", "write(")):
        return "file"
    if any(token in value for token in ("process", "thread", "inject", "virtualalloc", "writeprocessmemory", "createprocess", "execve", "fork")):
        return "process-memory"
    if any(token in value for token in ("crypto", "crypt", "encrypt", "decrypt", "bcrypt")):
        return "crypto"
    return "other"


def _emit(events: list[dict], source: str, source_ref: str, *, timestamp=None,
          pid=None, process=None, operation="event", target=None, details=None):
    events.append({
        "timestamp": _text(timestamp, 128) if timestamp is not None else None,
        "category": _category(str(operation)),
        "operation": str(operation)[:256],
        "pid": _text(pid, 64) if pid is not None else None,
        "process": _text(process, 512) if process is not None else None,
        "target": _text(target, 512) if target is not None else None,
        "details": _text(details, 512) if details is not None else None,
        "source": source,
        "source_ref": source_ref,
    })


def _cape_report(report: dict, source: str, events: list[dict]):
    behavior = report.get("behavior") or {}
    for process in behavior.get("processes") or []:
        pid = process.get("process_id", process.get("pid"))
        name = process.get("process_name", process.get("name"))
        for index, call in enumerate(process.get("calls") or []):
            api = call.get("api", call.get("name", "api-call"))
            args = call.get("arguments", call.get("args", {}))
            _emit(events, source, f"process[{pid}].calls[{index}]",
                  timestamp=call.get("timestamp"), pid=pid, process=name,
                  operation=api, target=args, details={"return": call.get("return"),
                                                       "category": call.get("category")})
            if len(events) >= MAX_EVENTS:
                return
    network = report.get("network") or {}
    for family in ("dns", "http", "tcp", "udp", "hosts", "domains"):
        entries = network.get(family) or []
        if isinstance(entries, dict):
            entries = [entries]
        for index, entry in enumerate(entries):
            _emit(events, source, f"network.{family}[{index}]", operation=family,
                  target=entry, details=entry)
            if len(events) >= MAX_EVENTS:
                return


SYSMON_CATEGORY = {
    1: "process-create", 3: "network-connect", 6: "driver-load",
    7: "image-load", 8: "remote-thread", 10: "process-access",
    11: "file-create", 12: "registry-change", 13: "registry-value-set",
    14: "registry-rename", 15: "file-stream-create", 17: "named-pipe-create",
    18: "named-pipe-connect", 22: "dns-query", 23: "file-delete",
    25: "process-tampering", 26: "file-delete-detected",
}


def _sysmon_event(event: dict, source: str, source_ref: str, events: list[dict]):
    if isinstance(event.get("Event"), dict):
        event = event["Event"]
    system = event.get("System") if isinstance(event.get("System"), dict) else {}
    event_data = event.get("EventData")
    if isinstance(event_data, dict):
        event = {**event, **event_data}
    event_id = event.get("EventID", event.get("event_id", event.get("id")))
    if event_id is None:
        event_id = system.get("EventID")
    try:
        event_id = int(event_id)
    except (TypeError, ValueError):
        event_id = -1
    operation = SYSMON_CATEGORY.get(event_id, f"sysmon-event-{event_id}")
    target = next((event.get(k) for k in (
        "DestinationHostname", "DestinationIp", "QueryName", "TargetFilename",
        "TargetObject", "ImageLoaded", "PipeName", "CommandLine", "Image")
                   if event.get(k) is not None), None)
    timestamp = event.get("UtcTime", event.get("timestamp"))
    if timestamp is None and isinstance(system.get("TimeCreated"), dict):
        timestamp = system["TimeCreated"].get("SystemTime")
    _emit(events, source, source_ref, timestamp=timestamp,
          pid=event.get("ProcessId", event.get("ProcessID")),
          process=event.get("Image", event.get("ProcessName")), operation=operation,
          target=target, details=event)


def _procmon(path: Path, events: list[dict]):
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as stream:
        reader = csv.DictReader(stream)
        for index, row in enumerate(reader, start=2):
            operation = row.get("Operation") or "procmon-event"
            details = {key: value for key, value in row.items()
                       if key not in {"Time of Day", "Process Name", "PID", "Operation", "Path"}}
            _emit(events, str(path), f"line:{index}",
                  timestamp=row.get("Time of Day"), pid=row.get("PID"),
                  process=row.get("Process Name"), operation=operation,
                  target=row.get("Path"), details=details)
            if len(events) >= MAX_EVENTS:
                return


def _parse_file(path: Path, events: list[dict], inputs: list[dict]):
    size = path.stat().st_size
    if size > MAX_INPUT_SIZE:
        inputs.append({"path": str(path), "size": size,
                       "error": f"exceeds {MAX_INPUT_SIZE} byte input limit"})
        return
    digest = _sha256(path)
    inputs.append({"path": str(path), "size": size, "sha256": digest})
    suffix = path.suffix.lower()
    if suffix == ".csv":
        _procmon(path, events)
        return
    content = path.read_text(encoding="utf-8-sig", errors="replace")
    if suffix in {".jsonl", ".ndjson"}:
        for line_number, line in enumerate(content.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                _sysmon_event(event, str(path), f"line:{line_number}", events)
            if len(events) >= MAX_EVENTS:
                return
        return
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        inputs[-1]["error"] = f"unsupported or invalid JSON/JSONL/CSV: {exc}"
        return
    if isinstance(data, list):
        for index, event in enumerate(data):
            if isinstance(event, dict):
                _sysmon_event(event, str(path), f"event:{index}", events)
    elif isinstance(data, dict) and ("behavior" in data or "network" in data):
        _cape_report(data, str(path), events)
    elif isinstance(data, dict):
        _sysmon_event(data, str(path), "event:0", events)


def _ioc_candidates(events: list[dict]) -> list[dict]:
    occurrences = Counter()
    for event in events:
        text = " ".join(str(event.get(k) or "") for k in ("target", "details"))
        for value in URL_RE.findall(text):
            occurrences[("url", value.rstrip(",;)]}"))] += 1
        for value in IP_RE.findall(text):
            try:
                ipaddress.ip_address(value)
            except ValueError:
                continue
            occurrences[("ip", value)] += 1
        for value in DOMAIN_RE.findall(text):
            occurrences[("domain", value.lower())] += 1
    return [{"type": kind, "value": value, "occurrences": count,
             "status": "candidate; validate against context and baseline traffic"}
            for (kind, value), count in sorted(occurrences.items())]


def normalize(source: str | Path, sample_sha256: str | None = None) -> dict:
    path = Path(source).expanduser().resolve()
    if not path.exists():
        return {"error": f"telemetry path does not exist: {path}"}
    if sample_sha256 is not None and not re.fullmatch(r"[0-9a-fA-F]{64}", sample_sha256):
        return {"error": "sample_sha256 must be exactly 64 hexadecimal characters"}
    paths = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
    events, inputs = [], []
    for item in paths:
        if item.suffix.lower() not in {".json", ".jsonl", ".ndjson", ".csv"}:
            continue
        if path.is_dir() and not item.resolve().is_relative_to(path):
            continue
        input_count = len(inputs)
        try:
            _parse_file(item, events, inputs)
        except Exception as exc:  # noqa: BLE001
            if len(inputs) == input_count:
                inputs.append({"path": str(item), "error": f"could not read telemetry: {exc}"})
            else:
                inputs[-1]["error"] = f"could not parse telemetry: {exc}"
        if len(events) >= MAX_EVENTS:
            break
    events.sort(key=lambda event: (event["timestamp"] is None,
                                   event["timestamp"] or "",
                                   event["source_ref"]))
    counts = Counter(event["category"] for event in events)
    return {
        "tool": "qi-nx-dynamic-evidence",
        "author": "Qi-NX",
        "source": str(path),
        "sample_sha256": sample_sha256.lower() if sample_sha256 else None,
        "sample_hash_provenance": "user-supplied; telemetry parser does not verify the sample binary" if sample_sha256 else "Not provided",
        "input_total": len(inputs),
        "event_total": len(events),
        "event_counts_by_category": dict(sorted(counts.items())),
        "ioc_candidates": _ioc_candidates(events),
        "inputs": inputs,
        "events": events,
        "truncated": len(events) >= MAX_EVENTS,
        "limitations": [
            "offline telemetry normalization only; this tool does not execute samples or control a sandbox",
            "supported formats are CAPE/Cuckoo JSON, Sysmon JSONL, and Procmon CSV exports",
            "IOC candidates may be benign; validate against event context and environmental baselines",
            "telemetry only records behavior observed during that specific sandbox run",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="CAPE/Cuckoo JSON, Sysmon JSONL, Procmon CSV, or directory of exports")
    parser.add_argument("--sample-sha256", help="known SHA-256 of the sample represented by this telemetry")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = normalize(args.source, args.sample_sha256)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif "error" in result:
        print(result["error"], file=sys.stderr)
        return 2
    else:
        print(f"# dynamic_evidence — {result['source']}\n# {BANNER}")
        print(f"inputs={result['input_total']} events={result['event_total']} "
              f"ioc_candidates={len(result['ioc_candidates'])}")
        for category, count in result["event_counts_by_category"].items():
            print(f"{category}: {count}")
        for ioc in result["ioc_candidates"][:50]:
            print(f"{ioc['type']}: {ioc['value']} ({ioc['occurrences']} events)")
    return 0 if "error" not in result else 2


if __name__ == "__main__":
    sys.exit(main())
