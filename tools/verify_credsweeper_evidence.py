#!/usr/bin/env python3
"""Validate value-free CredSweeper compatibility evidence for a release."""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
from typing import Any


TOTAL_FIELDS = ("rust", "oracle", "common", "missing", "extra")


def fail(message: str) -> None:
    raise SystemExit(f"invalid CredSweeper compatibility evidence: {message}")


def require_object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{name} must be an object")
    return value


def verify(
    evidence_path: Path,
    source_path: Path,
    creddata_snapshot: Path,
    *,
    pentect_commit: str,
    tested_ref: str,
    creddata_commit: str,
) -> None:
    evidence = require_object(
        json.loads(evidence_path.read_text(encoding="utf-8")), "root"
    )
    source = require_object(json.loads(source_path.read_text(encoding="utf-8")), "source")
    snapshot = require_object(
        json.loads(creddata_snapshot.read_text(encoding="utf-8")), "CredData snapshot"
    )

    if evidence.get("schema") != 3:
        fail("schema must be 3")
    expected_fields = {
        "schema",
        "generated_at",
        "pentect",
        "reference",
        "corpus",
        "environment",
        "workflow_run",
        "gates",
        "shards",
        "repositories",
        "metadata_files",
        "credsweeper_version",
        "ml_probability_max_delta",
        "ml_probability_tolerance",
        "ml_probability_within_tolerance",
        "by_rule",
        *TOTAL_FIELDS,
    }
    if set(evidence) != expected_fields:
        fail("top-level fields are incomplete or contain unapproved data")
    pentect = require_object(evidence.get("pentect"), "pentect")
    if pentect != {"commit": pentect_commit, "ref": tested_ref}:
        fail("Pentect commit or ref does not match the release")
    reference = require_object(evidence.get("reference"), "reference")
    if set(reference) != {"name", "version", "commit"}:
        fail("reference fields are incomplete or contain unapproved data")
    if reference.get("name") != "CredSweeper":
        fail("oracle name is not CredSweeper")
    if reference.get("version") != source.get("version"):
        fail("CredSweeper version does not match the embedded source metadata")
    if reference.get("commit") != source.get("commit"):
        fail("CredSweeper commit does not match the embedded source metadata")
    if evidence.get("credsweeper_version") != reference.get("version"):
        fail("duplicate CredSweeper version fields differ")

    corpus = require_object(evidence.get("corpus"), "corpus")
    if set(corpus) != {"name", "commit", "repositories", "metadata_files"}:
        fail("corpus fields are incomplete or contain unapproved data")
    if corpus.get("name") != "CredData" or corpus.get("commit") != creddata_commit:
        fail("CredData identity does not match the release checkout")
    if corpus.get("repositories") != len(snapshot):
        fail("CredData repository count does not match the pinned snapshot")
    if corpus.get("repositories") != evidence.get("repositories"):
        fail("top-level and corpus repository counts differ")
    if corpus.get("metadata_files") != evidence.get("metadata_files"):
        fail("top-level and corpus metadata counts differ")
    for name in ("shards", "repositories", "metadata_files"):
        value = evidence.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            fail(f"{name} must be a positive integer")

    gates = require_object(evidence.get("gates"), "gates")
    required_gates = {
        "full_creddata_parity",
        "full_filter_inventory_parity",
        "whole_pipeline_fixtures",
    }
    if set(gates) != required_gates or any(value is not True for value in gates.values()):
        fail("not every required compatibility gate passed")

    totals = {name: evidence.get(name) for name in TOTAL_FIELDS}
    if not all(
        not isinstance(value, bool) and isinstance(value, int) and value >= 0
        for value in totals.values()
    ):
        fail("finding totals must be non-negative integers")
    if totals["missing"] != 0 or totals["extra"] != 0:
        fail("native and official findings differ")
    if not totals["rust"] == totals["oracle"] == totals["common"]:
        fail("native, official, and common totals differ")
    ml_delta = evidence.get("ml_probability_max_delta")
    ml_tolerance = evidence.get("ml_probability_tolerance")
    if (
        isinstance(ml_delta, bool)
        or not isinstance(ml_delta, (int, float))
        or isinstance(ml_tolerance, bool)
        or not isinstance(ml_tolerance, (int, float))
    ):
        fail("ML probability evidence is missing")
    if ml_delta < 0 or ml_tolerance < 0 or ml_delta > ml_tolerance:
        fail("ML probability delta exceeds tolerance")
    if evidence.get("ml_probability_within_tolerance") is not True:
        fail("ML probability gate did not pass")

    by_rule = require_object(evidence.get("by_rule"), "by_rule")
    if not by_rule:
        fail("per-rule evidence is empty")
    for rule, raw_counts in by_rule.items():
        counts = require_object(raw_counts, f"by_rule[{rule!r}]")
        if set(counts) != set(TOTAL_FIELDS):
            fail(f"unexpected fields in per-rule evidence for {rule!r}")
        if any(
            isinstance(counts[name], bool)
            or not isinstance(counts[name], int)
            or counts[name] < 0
            for name in TOTAL_FIELDS
        ):
            fail(f"invalid counts for rule {rule!r}")
        if counts["missing"] or counts["extra"]:
            fail(f"native and official findings differ for rule {rule!r}")

    environment = require_object(evidence.get("environment"), "environment")
    if set(environment) != {"os", "architecture"}:
        fail("environment fields are incomplete or contain unapproved data")
    if not environment.get("os") or not environment.get("architecture"):
        fail("runner OS and architecture are required")
    generated_at = evidence.get("generated_at")
    if not isinstance(generated_at, str):
        fail("generated_at is required")
    try:
        datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    except ValueError:
        fail("generated_at is not an ISO-8601 timestamp")
    if not generated_at.endswith("Z"):
        fail("generated_at must be UTC")
    workflow_run = evidence.get("workflow_run")
    if not isinstance(workflow_run, str) or "/actions/runs/" not in workflow_run:
        fail("workflow run URL is missing")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--creddata-snapshot", type=Path, required=True)
    parser.add_argument("--pentect-commit", required=True)
    parser.add_argument("--tested-ref", required=True)
    parser.add_argument("--creddata-commit", required=True)
    args = parser.parse_args()
    verify(
        args.evidence,
        args.source,
        args.creddata_snapshot,
        pentect_commit=args.pentect_commit,
        tested_ref=args.tested_ref,
        creddata_commit=args.creddata_commit,
    )
    print("CredSweeper compatibility evidence matches the release")


if __name__ == "__main__":
    main()
