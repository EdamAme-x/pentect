"""Detector protocol and Span dataclass."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from engine.categories import Category


@dataclass(frozen=True)
class Span:
    start: int           # inclusive start index in text
    end: int             # exclusive end index in text
    category: Category
    source: str          # detector name: "rule" or "llm"
    confidence: float = 1.0

    @property
    def value(self) -> str:
        # caller is responsible for slicing text
        raise NotImplementedError  # pragma: no cover


def slice_span(text: str, span: Span) -> str:
    return text[span.start:span.end]


class Detector(Protocol):
    name: str

    def detect(self, text: str) -> list[Span]: ...
