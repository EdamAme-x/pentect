#!/usr/bin/env python3
"""Prepare and verify deterministic CredData shards for weekly parity CI."""

from __future__ import annotations

import argparse
import binascii
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


def prepare(root: Path, index: int, count: int, manifest: Path, version: str) -> None:
    if count < 1 or not 0 <= index < count:
        raise SystemExit(f"invalid shard {index}/{count}")
    snapshot_path = root / "snapshot.json"
    snapshot: dict[str, str] = load_json(snapshot_path)
    entries = sorted(snapshot.items(), key=lambda item: (short_id(item[0]), item[0]))
    selected = entries[index::count]
    if not selected:
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
            "repositories": [
                {"id": repo_id, "short_id": short_id(repo_id)}
                for repo_id, _ in selected
            ],
        },
    )
    print(f"prepared CredData shard {index + 1}/{count}: {len(selected)} repositories")


def summarize(root: Path, artifacts: Path, count: int, output: Path) -> None:
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
    versions: set[str] = set()
    for manifest_path in manifests:
        manifest = load_json(manifest_path)
        index = int(manifest["index"])
        if int(manifest["count"]) != count or index in seen_indices:
            raise SystemExit(f"invalid or duplicate manifest: {manifest_path}")
        seen_indices.add(index)
        versions.add(str(manifest["credsweeper_version"]))
        for repository in manifest["repositories"]:
            repo_id = repository["id"]
            if repo_id in seen_repositories:
                raise SystemExit(f"repository appears in multiple shards: {repo_id}")
            seen_repositories.add(repo_id)

        report_path = manifest_path.with_name("report.json")
        report = load_json(report_path)
        for key in totals:
            totals[key] += int(report[key])
        if int(report["missing"]) or int(report["extra"]):
            raise SystemExit(f"CredSweeper mismatch in shard {index}: {report_path}")
        if not bool(report["ml_probability_within_tolerance"]):
            raise SystemExit(f"ML probability mismatch in shard {index}: {report_path}")

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

    summary = {
        "schema": 1,
        "shards": count,
        "repositories": len(seen_repositories),
        "credsweeper_version": versions.pop(),
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
        summarize(args.root, args.artifacts, args.count, args.output)


if __name__ == "__main__":
    main()
