#!/usr/bin/env python3
"""Prepare and verify deterministic CredData shards for weekly parity CI."""

from __future__ import annotations

import argparse
import binascii
import csv
import json
from pathlib import Path
from typing import Any


def short_id(repo_id: str) -> str:
    return f"{binascii.crc32(bytes.fromhex(repo_id)):08x}"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def metadata_weight(root: Path, repo_id: str) -> int:
    """Estimate scan work from unique files, with one unit for empty metadata."""
    path = root / "meta" / f"{short_id(repo_id)}.csv"
    try:
        with path.open(encoding="utf-8", newline="") as stream:
            rows = csv.DictReader(stream)
            return max(1, len({row["FilePath"] for row in rows}))
    except FileNotFoundError as error:
        raise SystemExit(f"CredData metadata missing: {path}") from error


def partition(root: Path, repository_ids: list[str], count: int) -> list[list[str]]:
    """Greedily balance deterministic shards by CredData metadata volume."""
    shards: list[list[str]] = [[] for _ in range(count)]
    weights = [0] * count
    weighted = sorted(
        ((metadata_weight(root, repo_id), repo_id) for repo_id in repository_ids),
        key=lambda item: (-item[0], short_id(item[1]), item[1]),
    )
    for weight, repo_id in weighted:
        shard_index = min(range(count), key=lambda value: (weights[value], value))
        shards[shard_index].append(repo_id)
        weights[shard_index] += weight
    for shard in shards:
        shard.sort(key=lambda repo_id: (short_id(repo_id), repo_id))
    return shards


def prepare(root: Path, index: int, count: int, manifest: Path, version: str) -> None:
    if count < 1 or not 0 <= index < count:
        raise SystemExit(f"invalid shard {index}/{count}")
    snapshot_path = root / "snapshot.json"
    snapshot: dict[str, str] = load_json(snapshot_path)
    shards = partition(root, list(snapshot), count)
    selected_ids = shards[index]
    selected = [(repo_id, snapshot[repo_id]) for repo_id in selected_ids]
    if not selected_ids:
        raise SystemExit(f"shard {index}/{count} is empty")

    selected_short_ids = {short_id(repo_id) for repo_id, _ in selected}
    available_meta = {path.stem for path in (root / "meta").glob("*.csv")}
    missing_meta = selected_short_ids - available_meta
    if missing_meta:
        raise SystemExit(f"CredData metadata missing for: {sorted(missing_meta)}")

    write_json(snapshot_path, dict(selected))
    for path in (root / "meta").glob("*.csv"):
        if path.stem not in selected_short_ids:
            path.unlink()
    write_json(
        manifest,
        {
            "schema": 1,
            "index": index,
            "count": count,
            "credsweeper_version": version,
            "metadata_files": sum(metadata_weight(root, repo_id) for repo_id in selected_ids),
            "repositories": [
                {"id": repo_id, "short_id": short_id(repo_id)}
                for repo_id, _ in selected
            ],
        },
    )
    print(f"prepared CredData shard {index + 1}/{count}: {len(selected)} repositories")


def summarize(
    root: Path,
    artifacts: Path,
    count: int,
    output: Path,
    *,
    pentect_commit: str,
    tested_ref: str,
    credsweeper_commit: str,
    creddata_commit: str,
    tested_at: str,
    runner_os: str,
    runner_arch: str,
    workflow_run: str,
) -> None:
    expected: dict[str, str] = load_json(root / "snapshot.json")
    manifests = sorted(artifacts.glob("shard-*/manifest.json"))
    reports = sorted(artifacts.glob("shard-*/report.json"))
    if len(manifests) != count:
        raise SystemExit(f"expected {count} shard manifests, found {len(manifests)}")
    if len(reports) != count:
        raise SystemExit(f"expected {count} parity reports, found {len(reports)}")

    seen_indices: set[int] = set()
    seen_repositories: set[str] = set()
    totals = {key: 0 for key in ("rust", "oracle", "common", "missing", "extra")}
    by_rule: dict[str, dict[str, int]] = {}
    versions: set[str] = set()
    ml_tolerances: set[float] = set()
    ml_probability_max_delta = 0.0
    metadata_files = 0
    for manifest_path in manifests:
        manifest = load_json(manifest_path)
        index = int(manifest["index"])
        if int(manifest["count"]) != count or index in seen_indices:
            raise SystemExit(f"invalid or duplicate manifest: {manifest_path}")
        seen_indices.add(index)
        versions.add(str(manifest["credsweeper_version"]))
        metadata_files += int(manifest["metadata_files"])
        for repository in manifest["repositories"]:
            repo_id = repository["id"]
            if repo_id in seen_repositories:
                raise SystemExit(f"repository appears in multiple shards: {repo_id}")
            seen_repositories.add(repo_id)

        report_path = manifest_path.with_name("report.json")
        report = load_json(report_path)
        if report.get("schema") != 2:
            raise SystemExit(f"unsupported parity report schema: {report_path}")
        for key in totals:
            totals[key] += int(report[key])
        for rule, counts in report["by_rule"].items():
            aggregate = by_rule.setdefault(rule, {key: 0 for key in totals})
            for key in totals:
                aggregate[key] += int(counts[key])
        if int(report["missing"]) or int(report["extra"]):
            raise SystemExit(f"CredSweeper mismatch in shard {index}: {report_path}")
        if not bool(report["ml_probability_within_tolerance"]):
            raise SystemExit(f"ML probability mismatch in shard {index}: {report_path}")
        ml_probability_max_delta = max(
            ml_probability_max_delta, float(report["ml_probability_max_delta"])
        )
        ml_tolerances.add(float(report["ml_probability_tolerance"]))

    expected_repositories = set(expected)
    missing = expected_repositories - seen_repositories
    extra = seen_repositories - expected_repositories
    if missing or extra:
        raise SystemExit(
            f"shard coverage mismatch: missing={len(missing)} extra={len(extra)}"
        )
    if seen_indices != set(range(count)):
        raise SystemExit(f"shard index coverage mismatch: {sorted(seen_indices)}")
    if len(versions) != 1:
        raise SystemExit(f"shards used different CredSweeper versions: {sorted(versions)}")
    if len(ml_tolerances) != 1:
        raise SystemExit(f"shards used different ML tolerances: {sorted(ml_tolerances)}")

    credsweeper_version = versions.pop()
    summary = {
        "schema": 3,
        "generated_at": tested_at,
        "pentect": {"commit": pentect_commit, "ref": tested_ref},
        "reference": {
            "name": "CredSweeper",
            "version": credsweeper_version,
            "commit": credsweeper_commit,
        },
        "corpus": {
            "name": "CredData",
            "commit": creddata_commit,
            "repositories": len(seen_repositories),
            "metadata_files": metadata_files,
        },
        "environment": {"os": runner_os, "architecture": runner_arch},
        "workflow_run": workflow_run,
        "gates": {
            "full_creddata_parity": True,
            "full_filter_inventory_parity": True,
            "whole_pipeline_fixtures": True,
        },
        "shards": count,
        "repositories": len(seen_repositories),
        "metadata_files": metadata_files,
        "credsweeper_version": credsweeper_version,
        "ml_probability_max_delta": ml_probability_max_delta,
        "ml_probability_tolerance": ml_tolerances.pop(),
        "ml_probability_within_tolerance": True,
        "by_rule": dict(sorted(by_rule.items())),
        **totals,
    }
    write_json(output, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--root", type=Path, required=True)
    prepare_parser.add_argument("--index", type=int, required=True)
    prepare_parser.add_argument("--count", type=int, required=True)
    prepare_parser.add_argument("--manifest", type=Path, required=True)
    prepare_parser.add_argument("--credsweeper-version", required=True)
    summary_parser = commands.add_parser("summarize")
    summary_parser.add_argument("--root", type=Path, required=True)
    summary_parser.add_argument("--artifacts", type=Path, required=True)
    summary_parser.add_argument("--count", type=int, required=True)
    summary_parser.add_argument("--output", type=Path, required=True)
    summary_parser.add_argument("--pentect-commit", required=True)
    summary_parser.add_argument("--tested-ref", required=True)
    summary_parser.add_argument("--credsweeper-commit", required=True)
    summary_parser.add_argument("--creddata-commit", required=True)
    summary_parser.add_argument("--tested-at", required=True)
    summary_parser.add_argument("--runner-os", required=True)
    summary_parser.add_argument("--runner-arch", required=True)
    summary_parser.add_argument("--workflow-run", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "prepare":
        prepare(
            args.root,
            args.index,
            args.count,
            args.manifest,
            args.credsweeper_version,
        )
    else:
        summarize(
            args.root,
            args.artifacts,
            args.count,
            args.output,
            pentect_commit=args.pentect_commit,
            tested_ref=args.tested_ref,
            credsweeper_commit=args.credsweeper_commit,
            creddata_commit=args.creddata_commit,
            tested_at=args.tested_at,
            runner_os=args.runner_os,
            runner_arch=args.runner_arch,
            workflow_run=args.workflow_run,
        )


if __name__ == "__main__":
    main()
