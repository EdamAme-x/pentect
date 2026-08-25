from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

try:
    from credsweeper.paths import APP_PATH
except ModuleNotFoundError:
    import credsweeper

    APP_PATH = Path(credsweeper.__file__).resolve().parent
from credsweeper.common.constants import Severity, ThresholdPreset
from credsweeper.config.config import Config
from credsweeper.credentials.candidate import Candidate
from credsweeper.credentials.candidate_key import CandidateKey
from credsweeper.file_handler.text_content_provider import TextContentProvider
from credsweeper.ml_model.ml_validator import MlValidator
from credsweeper.scanner.scanner import Scanner
from credsweeper.utils.util import Util


def build_config(use_filters: bool) -> Config:
    config_dict = Util.json_load(APP_PATH / "secret" / "config.json")
    config_dict["use_filters"] = use_filters
    config_dict["find_by_ext"] = False
    config_dict["size_limit"] = None
    config_dict["pedantic"] = False
    config_dict["depth"] = 0
    config_dict["doc"] = False
    config_dict["severity"] = Severity.INFO.value
    return Config(config_dict)


def purge_duplicates(candidates: list[Candidate]) -> list[Candidate]:
    out: list[Candidate] = []
    seen: set[tuple[Any, ...]] = set()
    for candidate in candidates:
        line_data = candidate.line_data_list[0]
        key = (
            candidate.rule_name,
            line_data.path,
            line_data.info,
            line_data.line_pos,
            line_data.variable_start,
            line_data.variable_end,
            line_data.separator_start,
            line_data.separator_end,
            line_data.value_start,
            line_data.value_end,
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(candidate)
    return out


def group_credentials(candidates: list[Candidate]) -> list[tuple[CandidateKey, list[Candidate]]]:
    groups: dict[CandidateKey, list[Candidate]] = {}
    for candidate in candidates:
        for line_data in candidate.line_data_list[:1]:
            key = CandidateKey(line_data)
            groups.setdefault(key, []).append(candidate)
    return list(groups.items())


def apply_ml(candidates: list[Candidate], batch_size: int) -> list[Candidate]:
    result: list[Candidate] = []
    ml_groups: list[tuple[CandidateKey, list[Candidate]]] = []
    for group_key, group_candidates in group_credentials(candidates):
        if any(candidate.use_ml for candidate in group_candidates):
            ml_groups.append((group_key, group_candidates))
        else:
            result.extend(group_candidates)
    if not ml_groups:
        return result

    validator = MlValidator(ThresholdPreset.medium)
    is_cred, probability = validator.validate_groups(ml_groups, batch_size)
    for index, (_, group_candidates) in enumerate(ml_groups):
        for candidate in group_candidates:
            if candidate.use_ml:
                if is_cred[index]:
                    candidate.ml_probability = float(probability[index])
                    result.append(candidate)
            else:
                result.append(candidate)
    return result


def scan_paths(paths: list[Path], use_filters: bool, use_ml: bool, batch_size: int) -> list[dict[str, Any]]:
    config = build_config(use_filters)
    scanner = Scanner(config, None)
    credentials: list[dict[str, Any]] = []
    for path in paths:
        candidates = purge_duplicates(scanner.scan(TextContentProvider(path)))
        if use_ml:
            candidates = apply_ml(candidates, batch_size)
        credentials.extend(candidate.to_json(hashed=False, subtext=False) for candidate in candidates)
    return credentials


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="pentect-credsweeper-sidecar")
    parser.add_argument("paths", nargs="*", type=Path)
    parser.add_argument(
        "--paths-file",
        type=Path,
        help="newline-delimited paths (avoids platform command-line length limits)",
    )
    parser.add_argument("--no-filters", action="store_true")
    parser.add_argument("--no-ml", action="store_true")
    parser.add_argument("--ml-batch-size", type=int, default=16)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    paths = list(args.paths)
    if args.paths_file:
        paths.extend(
            Path(line)
            for line in args.paths_file.read_text(encoding="utf-8").splitlines()
            if line
        )
    if not paths:
        raise SystemExit("at least one path or --paths-file is required")
    credentials = scan_paths(
        paths,
        use_filters=not args.no_filters,
        use_ml=not args.no_ml,
        batch_size=max(1, args.ml_batch_size),
    )
    data = json.dumps(credentials, ensure_ascii=False)
    if args.output:
        args.output.write_text(data, encoding="utf-8")
    else:
        print(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
