"""Placeholder generation.

Format: <<CATEGORY_hash8>>
- hash8 is the first 8 hex digits of SHA256(value)
- identical values always produce the same placeholder
"""
from __future__ import annotations

import hashlib

from engine.categories import Category


HASH_LEN = 8


def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:HASH_LEN]


def make_placeholder(category: Category, value: str, suffix: str | None = None) -> str:
    """Generate a placeholder string.

    suffix differentiates sub-parts within a category (e.g. HOST vs ID in URLs).
    """
    h = hash_value(value)
    label = category.value if suffix is None else f"{category.value}_{suffix}"
    return f"<<{label}_{h}>>"


def describe_placeholder(category: Category, placeholder: str) -> str:
    """Human-readable description for summary output."""
    from engine.categories import get_spec

    spec = get_spec(category)
    return f"{placeholder}: {spec.description}"
