"""Test case YAML schema — one file per case."""
from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field


class SecretExpectation(BaseModel):
    value: str
    expected_category: str


class ContextPreservation(BaseModel):
    prompt: str
    expected_keywords: list[str]
    min_match: int = 1


class TestCase(BaseModel):
    id: str
    category: Literal["har", "text"] = "har"
    description: str = ""
    input_file: str | None = None  # path relative to the test case YAML
    input_text: str | None = None  # inline input for small cases
    secrets: list[SecretExpectation] = Field(default_factory=list)
    context_preservation: list[ContextPreservation] = Field(default_factory=list)
    must_not_mask: list[str] = Field(default_factory=list)

    def resolve_input(self, base_dir: Path) -> str:
        if self.input_text is not None:
            return self.input_text
        if self.input_file is None:
            raise ValueError(f"test case {self.id}: input_file or input_text is required")
        path = (base_dir / self.input_file).resolve()
        return path.read_text(encoding="utf-8")


def load_testcase(path: Path) -> TestCase:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return TestCase.model_validate(data)


def load_testcases_from_dir(dir_path: Path) -> list[tuple[Path, TestCase]]:
    out: list[tuple[Path, TestCase]] = []
    for p in sorted(dir_path.rglob("*.yaml")):
        try:
            out.append((p, load_testcase(p)))
        except Exception as e:  # noqa: BLE001
            raise ValueError(f"failed to load {p}: {e}") from e
    return out
