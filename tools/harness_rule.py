#!/usr/bin/env python3
"""OMCBench frozen harness rule: a static second opinion computed after a run (stdlib only).

Reads only the saved results.jsonl and chats/NNNN.static_analysis.json of a run directory.
It never opens package archives, never calls the model and never changes a model verdict.
The rule uses behaviour facts only: no archive format, size or directory structure.

Usage: python3 -I -B tools/harness_rule.py runs/<run_dir>
Writes <run_dir>/harness_rule_results.csv and <run_dir>/harness_rule_metrics.json.
"""

import csv
import hashlib
import json
from pathlib import Path
import re
import sys

RULE_VERSION = "R1-frozen-on-dev150"
# Tests, docs and generated bundles are not what runs when the package is installed or imported.
SKIP_PATH = re.compile(
    r"(^|/)(tests?|__tests__|docs?|examples?|fixtures|benchmarks?|node_modules)(/|$)"
    r"|(^|/)(test_|spec_)|\.(min\.js|map|d\.ts)$",
    re.I,
)
STRONG_NAMES = {"exfil_service", "bare_ip_url", "decode_and_exec", "pipe_to_shell", "encoded_powershell"}
SOURCE_KINDS = {"environment_read", "host_identity_read"}
DECODED_ACTION = re.compile(r"exec|eval|urlopen|requests|http|system|powershell|curl|wget", re.I)


def _first_line(observations, wanted):
    for obs in observations:
        if wanted(set(obs.get("kinds", []))):
            return obs.get("line")
    return None


def evaluate_rule(analysis_by_file):
    """Return the rule verdict and the facts behind it, as path:line references."""
    reasons = []
    for archive_path, item in analysis_by_file.items():
        # "path" has the wrapper directory removed, so a root named test_* does not hide the package.
        path = item.get("path", archive_path)
        if SKIP_PATH.search(path):
            continue
        observations = item.get("observations", [])
        kinds = {kind for obs in observations for kind in obs.get("kinds", [])}
        for name in sorted(STRONG_NAMES):
            kind = f"strong_indicator:{name}"
            if kind in kinds:
                line = _first_line(observations, lambda k: kind in k)
                reasons.append(f"{name} at {path}:{line}")
        for decoded in item.get("decoded_base64", []):
            if DECODED_ACTION.search(decoded.get("decoded", "")):
                reasons.append(f"decoded_payload_with_action at {path}:{decoded.get('line')}")
        if kinds & SOURCE_KINDS and "http_request" in kinds:
            source = _first_line(observations, lambda k: k & SOURCE_KINDS)
            sink = _first_line(observations, lambda k: "http_request" in k)
            reasons.append(f"env_or_host_read at {path}:{source} with http_request at line {sink}")
    return ("malicious" if reasons else "benign"), reasons


def confusion(rows, predict):
    tp = fp = fn = tn = 0
    for row in rows:
        positive = predict(row)
        if row["label_true"] == "malicious":
            tp, fn = tp + positive, fn + (not positive)
        else:
            fp, tn = fp + positive, tn + (not positive)
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0,
    }


def summarize(rows):
    report = {
        "n": len(rows),
        # A failed triage has no model verdict and counts as not malicious.
        "model": confusion(rows, lambda r: r["model_verdict"] == "malicious"),
        "rule": confusion(rows, lambda r: r["rule_verdict"] == "malicious"),
        "model_or_rule": confusion(
            rows, lambda r: r["model_verdict"] == "malicious" or r["rule_verdict"] == "malicious"),
        "model_and_rule": confusion(
            rows, lambda r: r["model_verdict"] == "malicious" and r["rule_verdict"] == "malicious"),
        "agreement": {},
    }
    for row in rows:
        key = f"{row['agreement']}/{row['label_true']}"
        report["agreement"][key] = report["agreement"].get(key, 0) + 1
    return report


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    run_dir = Path(sys.argv[1])
    results = [json.loads(line) for line in (run_dir / "results.jsonl").open(encoding="utf-8")]
    rows = []
    for result in results:
        static_path = run_dir / "chats" / f"{result['sample_id']:04d}.static_analysis.json"
        analysis = {}
        if static_path.exists():
            analysis = json.loads(static_path.read_text(encoding="utf-8")).get("analysis_by_file", {})
        rule_verdict, reasons = evaluate_rule(analysis)
        model_verdict = result.get("verdict") if result.get("status") == "completed" else "no_verdict"
        model_positive = model_verdict == "malicious"
        rule_positive = rule_verdict == "malicious"
        agreement = {
            (True, True): "both_malicious",
            (False, True): "harness_only",
            (True, False): "model_only",
            (False, False): "both_benign",
        }[(model_positive, rule_positive)]
        rows.append({
            "archive": result["archive"],
            "ecosystem": result["ecosystem"],
            "label_true": result["label_true"],
            "status": result.get("status"),
            "model_verdict": model_verdict,
            "rule_verdict": rule_verdict,
            "system_verdict": "malicious" if model_positive or rule_positive else "benign",
            "agreement": agreement,
            "static_facts_found": bool(analysis),
            "rule_reasons": "; ".join(reasons[:6]),
            "model_reasoning": " ".join(str(result.get("reasoning") or "").split())[:600],
        })
    with (run_dir / "harness_rule_results.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    report = {
        "rule_version": RULE_VERSION,
        "rule_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "packages_without_static_facts": sum(not r["static_facts_found"] for r in rows),
        "overall": summarize(rows),
        "ecosystems": {
            eco: summarize([r for r in rows if r["ecosystem"] == eco]) for eco in ("npm", "pypi")
        },
    }
    (run_dir / "harness_rule_metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({k: report["overall"][k] for k in ("n", "model", "rule", "model_or_rule", "agreement")}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
