#!/usr/bin/env python3
"""Validate successful, argument-free persistent lifecycle records."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path)
    parser.add_argument("surfaces", nargs="+")
    parser.add_argument("--absent", action="append", default=[])
    args = parser.parse_args()

    raw = args.log.read_text(encoding="utf-8")
    for forbidden in args.absent:
        assert forbidden not in raw, f"persistent log captured forbidden text: {forbidden}"
    events = [json.loads(line) for line in raw.splitlines() if line.strip()]
    for surface in args.surfaces:
        assert any(
            event.get("event") == "finished"
            and event.get("surface") == surface
            and event.get("exit_code") == 0
            for event in events
        ), f"successful {surface} lifecycle was not persisted"


if __name__ == "__main__":
    main()
