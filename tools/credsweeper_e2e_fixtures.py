#!/usr/bin/env python3
"""Generate value-safe native/oracle fixtures and validate their scan output."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def prepare(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    cases = {
        "unicode.txt": "password = “A7mQ9xL2pR8vN4kZ”\n",
        "multiline.env": "AWS_ACCESS_KEY_ID=A" + "KIA" + "LJDBECWDLOOWXROV\n"
        "AWS_SECRET_ACCESS_KEY=" + "Lplsx2J0OaHPJoG7U7kp" + "bhGUvnQ7Yv3O7zN3XXus\n",
        "filtered-multiline.env": "AWS_ACCESS_KEY_ID=A" + "KIA" + "QWERTYUIOP123456\n"
        "AWS_SECRET_ACCESS_KEY=" + "aB3/" * 10 + "\n",
        "filtered-alibaba.env": "access_key_id=LT" + "AI1234567890ABCDEF\n"
        "access_key_secret=" + "G7mQ9xL2pR8vN4kZaB6cD3fH5jT1wS\n",
        "filtered-google.txt": "123-" + "a" * 32 + ".apps.googleusercontent.com\n"
        "GO" + "CSPX-FAsZauZ28P3STmkBhqQi1Y-EsEaX\n",
        "encoded.txt": "oauth_token%3Dkgwv659s32kh9kot%26next%3Dvalue\n",
        "allowlisted.py": 'password = "${SECRET_NAME}"\n',
        "malformed.txt": 'token = "unterminated\npassword = []\n秘密 = 🚀\n',
    }
    for name, value in cases.items():
        (root / name).write_text(value, encoding="utf-8", newline="\n")
    (root / "paths.txt").write_text(
        "".join(f"{root / name}\n" for name in cases), encoding="utf-8"
    )


def verify(findings_path: Path, root: Path) -> None:
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    if not findings:
        raise SystemExit("differential fixtures produced no positive findings")
    paths = {
        Path(line["path"]).name
        for finding in findings
        for line in finding.get("line_data_list", [])
    }
    required = {"unicode.txt", "multiline.env", "encoded.txt"}
    missing = sorted(required - paths)
    if missing:
        raise SystemExit(f"positive differential fixtures were not detected: {missing}")
    forbidden_rules = {
        "filtered-multiline.env": "AWS Multi",
        "filtered-alibaba.env": "Alibaba Multi",
        "filtered-google.txt": "Google Multi",
    }
    violations = set()
    for finding in findings:
        rule = finding.get("rule")
        for line in finding.get("line_data_list", []):
            name = Path(line["path"]).name
            if name in {"allowlisted.py", "malformed.txt"} or forbidden_rules.get(name) == rule:
                violations.add((name, rule))
    if violations:
        raise SystemExit(f"negative differential fixtures produced findings: {sorted(violations)}")
    print(
        f"CredSweeper E2E fixtures: {len(findings)} findings "
        f"across {len(paths)} files with accepted findings"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("root", type=Path)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("findings", type=Path)
    verify_parser.add_argument("root", type=Path)
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args.root)
    else:
        verify(args.findings, args.root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
