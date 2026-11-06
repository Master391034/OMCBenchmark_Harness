#!/usr/bin/env python3
"""Create reproducible OMCBench Development-150 and holdout splits.

Reads only manifest.csv and the smoke package list. It does not open or extract
package archives. Existing output files are never overwritten.
"""
import argparse
import csv
import hashlib
import json
import random
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

SEED = 20261103
QUOTAS = {
    ("py", "benign"): 38,
    ("py", "malicious"): 37,
    ("js", "benign"): 37,
    ("js", "malicious"): 38,
}
EXPECTED_ECOSYSTEMS = {"py", "js"}
EXPECTED_LABELS = {"benign", "malicious"}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def read_names(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8-sig").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--smoke", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()

    manifest_path = args.manifest.resolve()
    smoke_path = args.smoke.resolve()
    out_dir = args.out_dir.resolve()

    with manifest_path.open(newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))

    required = {"folder_name", "ecosystem", "label_true"}
    if not rows or not required.issubset(rows[0]):
        raise SystemExit(f"Manifest must contain columns: {sorted(required)}")
    if len(rows) != 800:
        raise SystemExit(f"Expected 800 manifest rows, got {len(rows)}")

    names = [r["folder_name"] for r in rows]
    if len(names) != len(set(names)):
        raise SystemExit("Manifest contains duplicate folder_name values")

    smoke_names = read_names(smoke_path)
    if len(smoke_names) != len(set(smoke_names)):
        raise SystemExit("Smoke list contains duplicate archive names")
    unknown_smoke = sorted(set(smoke_names) - set(names))
    if unknown_smoke:
        raise SystemExit(f"Smoke list contains names absent from manifest: {unknown_smoke}")

    remaining = []
    for r in rows:
        if r["ecosystem"] not in EXPECTED_ECOSYSTEMS:
            raise SystemExit(f"Unexpected ecosystem value: {r['ecosystem']!r}")
        if r["label_true"] not in EXPECTED_LABELS:
            raise SystemExit(f"Unexpected label_true value: {r['label_true']!r}")
        if r["folder_name"] not in set(smoke_names):
            remaining.append(r)

    if len(remaining) != 797:
        raise SystemExit(f"Expected 797 rows after smoke exclusion, got {len(remaining)}")

    strata = defaultdict(list)
    for r in remaining:
        strata[(r["ecosystem"], r["label_true"])].append(r)

    expected_strata = {
        ("py", "benign"): 199,
        ("py", "malicious"): 199,
        ("js", "benign"): 199,
        ("js", "malicious"): 200,
    }
    for key, expected in expected_strata.items():
        actual = len(strata[key])
        if actual != expected:
            raise SystemExit(f"Unexpected remaining stratum size for {key}: {actual}, expected {expected}")

    rng = random.Random(args.seed)
    selected = set()
    for key in sorted(QUOTAS):
        quota = QUOTAS[key]
        if quota > len(strata[key]):
            raise SystemExit(f"Quota exceeds stratum size for {key}")
        selected.update(r["folder_name"] for r in rng.sample(strata[key], quota))

    # Keep original manifest order in both files; selection itself is seeded.
    dev_rows = [r for r in remaining if r["folder_name"] in selected]
    holdout_rows = [r for r in remaining if r["folder_name"] not in selected]

    if len(dev_rows) != 150 or len(holdout_rows) != 647:
        raise SystemExit("Internal split-size validation failed")
    if set(r["folder_name"] for r in dev_rows) & set(r["folder_name"] for r in holdout_rows):
        raise SystemExit("Development/holdout overlap detected")
    if set(r["folder_name"] for r in dev_rows) & set(smoke_names):
        raise SystemExit("Development/smoke overlap detected")
    if set(r["folder_name"] for r in holdout_rows) & set(smoke_names):
        raise SystemExit("Holdout/smoke overlap detected")

    out_dir.mkdir(parents=True, exist_ok=True)
    outputs = [
        out_dir / "dev-150.txt",
        out_dir / "holdout-647.txt",
        out_dir / "split_manifest.csv",
        out_dir / "split_metadata.json",
    ]
    existing = [str(p) for p in outputs if p.exists()]
    if existing:
        raise SystemExit("Refusing to overwrite existing files: " + ", ".join(existing))

    (out_dir / "dev-150.txt").write_text(
        "\n".join(r["folder_name"] for r in dev_rows) + "\n", encoding="utf-8"
    )
    (out_dir / "holdout-647.txt").write_text(
        "\n".join(r["folder_name"] for r in holdout_rows) + "\n", encoding="utf-8"
    )

    with (out_dir / "split_manifest.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["split", "folder_name", "ecosystem", "label_true"]
        )
        writer.writeheader()
        for split, subset in (("development", dev_rows), ("holdout", holdout_rows)):
            for r in subset:
                writer.writerow({
                    "split": split,
                    "folder_name": r["folder_name"],
                    "ecosystem": r["ecosystem"],
                    "label_true": r["label_true"],
                })

    def counts(subset):
        c = Counter((r["ecosystem"], r["label_true"]) for r in subset)
        return {
            f"{eco}_{label}": c[(eco, label)]
            for eco in ("py", "js")
            for label in ("benign", "malicious")
        }

    metadata = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "seed": args.seed,
        "manifest_path": str(manifest_path),
        "manifest_sha256": sha256(manifest_path),
        "smoke_list_path": str(smoke_path),
        "smoke_list_sha256": sha256(smoke_path),
        "smoke_excluded": len(smoke_names),
        "smoke_archives": smoke_names,
        "remaining_after_smoke": len(remaining),
        "development_size": len(dev_rows),
        "holdout_size": len(holdout_rows),
        "development_strata": counts(dev_rows),
        "holdout_strata": counts(holdout_rows),
        "quota": {f"{k[0]}_{k[1]}": v for k, v in QUOTAS.items()},
        "selection_method": "independent seeded random sample within each ecosystem x label stratum",
        "archive_contents_opened": False,
    }
    (out_dir / "split_metadata.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    print(json.dumps({
        "status": "success",
        "seed": args.seed,
        "smoke_excluded": len(smoke_names),
        "development_size": len(dev_rows),
        "holdout_size": len(holdout_rows),
        "development_strata": counts(dev_rows),
        "holdout_strata": counts(holdout_rows),
        "outputs": [str(p) for p in outputs],
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
