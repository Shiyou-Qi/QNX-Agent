#!/usr/bin/env python3
"""Compile YARA rules and measure them against a labeled malware-analysis corpus.

Corpus manifest format:
{
  "samples": [
    {"path": "positive.bin", "labels": {"rule_name": true}},
    {"path": "negative.bin", "labels": {"rule_name": false}}
  ]
}

Only explicitly labeled (sample, rule) pairs contribute to quality metrics.
Usage: python yara_backtest.py <corpus_dir> --rules <file-or-dir> [--manifest JSON] [--json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from collections import defaultdict
from pathlib import Path

BANNER = "by Qi-NX-Agent (Copyright Qi-NX)"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _compile(yara, rule_path: Path):
    if not rule_path.exists():
        raise ValueError(f"rules path does not exist: {rule_path}")
    if rule_path.is_dir():
        paths = sorted(list(rule_path.rglob("*.yar")) + list(rule_path.rglob("*.yara")))
        if not paths:
            raise ValueError(f"no .yar/.yara files found under: {rule_path}")
        return yara.compile(filepaths={str(path): str(path) for path in paths})
    return yara.compile(filepath=str(rule_path))


def _load_samples(corpus: Path, manifest_path: Path | None, max_samples: int):
    if not corpus.is_dir():
        raise ValueError(f"corpus is not a directory: {corpus}")
    if manifest_path is None:
        paths = sorted(p for p in corpus.rglob("*") if p.is_file())
        return [{"path": str(p.relative_to(corpus)), "labels": {}} for p in paths[:max_samples]], len(paths) > max_samples

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    items = manifest.get("samples") if isinstance(manifest, dict) else None
    if not isinstance(items, list):
        raise ValueError("manifest must be a JSON object with a 'samples' list")
    selected = []
    for item in items[:max_samples]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise ValueError("each manifest sample must have a string 'path'")
        labels = item.get("labels", {})
        if not isinstance(labels, dict) or any(not isinstance(v, bool) for v in labels.values()):
            raise ValueError(f"labels for {item['path']} must map rule names to true/false")
        if any(not isinstance(name, str) or not name for name in labels):
            raise ValueError(f"labels for {item['path']} must use non-empty rule names")
        expected_sha256 = item.get("sha256")
        if manifest_path and expected_sha256 is None:
            raise ValueError(f"manifest sample {item['path']} must pin its sha256 for reproducible metrics")
        if expected_sha256 is not None and (not isinstance(expected_sha256, str)
                                             or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256)):
            raise ValueError(f"sha256 for {item['path']} must be 64 hexadecimal characters")
        relative = Path(item["path"])
        resolved = (corpus / relative).resolve()
        if relative.is_absolute() or not resolved.is_relative_to(corpus.resolve()):
            raise ValueError(f"sample path escapes corpus directory: {item['path']}")
        selected.append({"path": item["path"], "labels": labels,
                         "expected_sha256": expected_sha256})
    return selected, len(items) > max_samples


def backtest(corpus: str | Path, rules_path: str | Path,
             manifest_path: str | Path | None = None,
             max_samples: int = 500, max_file_mb: int = 256,
             per_file_timeout: int = 30,
             total_timeout: int = 900) -> dict:
    """Scan a bounded corpus and calculate per-rule metrics for labeled pairs."""
    try:
        import yara
    except ImportError:
        return {"error": "yara-python not installed; run `python -m pip install yara-python`"}

    corpus_path = Path(corpus).expanduser().resolve()
    rule_path = Path(rules_path).expanduser().resolve()
    manifest = Path(manifest_path).expanduser().resolve() if manifest_path else None
    if max_samples < 1 or max_samples > 10000:
        return {"error": "max_samples must be between 1 and 10000"}
    if max_file_mb < 1 or max_file_mb > 4096:
        return {"error": "max_file_mb must be between 1 and 4096"}
    if total_timeout < 10 or total_timeout > 7200:
        return {"error": "total_timeout must be between 10 and 7200 seconds"}
    try:
        compiled = _compile(yara, rule_path)
        samples, truncated = _load_samples(corpus_path, manifest, max_samples)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"could not prepare YARA backtest: {exc}"}
    rule_files = ([rule_path] if rule_path.is_file() else
                  sorted(list(rule_path.rglob("*.yar")) + list(rule_path.rglob("*.yara"))))
    rule_root = rule_path.parent if rule_path.is_file() else rule_path
    rule_file_hashes = [{
        "path": str(item.relative_to(rule_root)).replace("\\", "/"),
        "sha256": _sha256(item),
    } for item in rule_files]
    ruleset_digest = hashlib.sha256()
    for item in rule_file_hashes:
        ruleset_digest.update(item["path"].encode("utf-8", errors="replace"))
        ruleset_digest.update(b"\0")
        ruleset_digest.update(item["sha256"].encode("ascii"))

    outcomes = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0,
                                    "labeled": 0, "unlabeled_hits": 0})
    results = []
    total_matches = 0
    started = time.monotonic()
    timed_out = False
    for sample in samples:
        if time.monotonic() - started >= total_timeout:
            timed_out = True
            break
        path = (corpus_path / sample["path"]).resolve()
        if not path.is_relative_to(corpus_path):
            results.append({"path": sample["path"], "error": "path escapes corpus"})
            continue
        if not path.is_file():
            results.append({"path": sample["path"], "error": "sample is missing"})
            continue
        size = path.stat().st_size
        if size > max_file_mb * 1024 * 1024:
            results.append({"path": sample["path"], "size": size,
                            "error": f"exceeds max_file_mb={max_file_mb}"})
            continue
        digest = _sha256(path)
        if sample.get("expected_sha256") and sample["expected_sha256"].lower() != digest:
            results.append({"path": sample["path"], "sha256": digest,
                            "error": "sha256 does not match manifest"})
            continue
        try:
            matches = compiled.match(filepath=str(path), timeout=per_file_timeout)
        except Exception as exc:  # noqa: BLE001
            results.append({"path": sample["path"], "sha256": digest,
                            "error": f"YARA scan failed: {exc}"})
            continue
        actual = sorted({match.rule for match in matches})
        actual_set = set(actual)
        labels = sample["labels"]
        total_matches += len(actual)
        for rule, expected in labels.items():
            got = rule in actual_set
            metric = outcomes[rule]
            metric["labeled"] += 1
            if expected and got:
                metric["tp"] += 1
            elif expected:
                metric["fn"] += 1
            elif got:
                metric["fp"] += 1
            else:
                metric["tn"] += 1
        for rule in actual_set - set(labels):
            outcomes[rule]["unlabeled_hits"] += 1
        results.append({"path": sample["path"], "size": size,
                        "sha256": digest, "actual_rules": actual,
                        "labels": labels, "unlabeled_hits": sorted(actual_set - set(labels))})

    metrics = {}
    for rule, counts in sorted(outcomes.items()):
        tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
        metrics[rule] = {
            **counts,
            "precision": round(tp / (tp + fp), 4) if tp + fp else None,
            "recall": round(tp / (tp + fn), 4) if tp + fn else None,
            "f1": round(2 * tp / (2 * tp + fp + fn), 4) if 2 * tp + fp + fn else None,
        }
    return {
        "tool": "qi-nx-yara-backtest",
        "author": "Qi-NX",
        "yara_version": getattr(yara, "__version__", "unknown"),
        "corpus": str(corpus_path),
        "rules": str(rule_path),
        "rule_files": rule_file_hashes,
        "ruleset_sha256": ruleset_digest.hexdigest(),
        "manifest": str(manifest) if manifest else None,
        "manifest_sha256": _sha256(manifest) if manifest else None,
        "mode": "labeled-quality-metrics" if manifest else "matches-only-no-ground-truth",
        "sample_total": len(results),
        "samples_selected": len(samples),
        "total_timeout_seconds": total_timeout,
        "timed_out": timed_out,
        "match_total": total_matches,
        "truncated": truncated,
        "per_rule_metrics": metrics,
        "samples": results,
        "limitations": [
            "quality metrics use only explicit labels for each (sample, rule) pair",
            "manifest hashes pin the scanned sample bytes but do not guarantee that labels are correct",
            "unlabeled matches are reported but are not counted as false positives",
            "results depend on corpus representativeness and label quality",
            "samples are read and scanned; they are never executed",
            "the total-time cap can stop before every selected sample has been scanned",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", help="directory of samples (read-only scan)")
    parser.add_argument("--rules", required=True, help="YARA rule file or directory")
    parser.add_argument("--manifest", help="JSON labels manifest; enables quality metrics")
    parser.add_argument("--max-samples", type=int, default=500)
    parser.add_argument("--max-file-mb", type=int, default=256)
    parser.add_argument("--timeout", type=int, default=30, help="per-sample YARA timeout in seconds")
    parser.add_argument("--total-timeout", type=int, default=900,
                        help="wall-clock cap for the full corpus scan in seconds")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = backtest(args.corpus, args.rules, args.manifest, args.max_samples,
                      args.max_file_mb, args.timeout, args.total_timeout)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif "error" in result:
        print(result["error"], file=sys.stderr)
        return 2
    else:
        print(f"# yara_backtest — {result['corpus']}\n# {BANNER}")
        print(f"mode={result['mode']} samples={result['sample_total']}/{result['samples_selected']} "
              f"matches={result['match_total']} timed_out={result['timed_out']}")
        for rule, metric in result["per_rule_metrics"].items():
            print(f"{rule}: TP={metric['tp']} FP={metric['fp']} FN={metric['fn']} "
                  f"TN={metric['tn']} precision={metric['precision']} recall={metric['recall']} "
                  f"F1={metric['f1']}")
        if result["truncated"]:
            print("sample list capped; raise --max-samples to include all entries")
    return 0 if "error" not in result else 2


if __name__ == "__main__":
    sys.exit(main())
