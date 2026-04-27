"""Category definitions and granularity modes (minimal PoC set)."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Category(str, Enum):
    CREDENTIAL = "CREDENTIAL"
    INTERNAL_URL = "INTERNAL_URL"
    INTERNAL_IP = "INTERNAL_IP"
    PII_EMAIL = "PII_EMAIL"
    PII_NAME = "PII_NAME"
    USER_ID = "USER_ID"


class GranularityMode(str, Enum):
    FULL = "full"                      # replace entire value with one placeholder
    URL_STRUCTURED = "url_structured"  # mask host + trailing ID, keep path structure
    EMAIL_LOCAL = "email_local"        # mask local part only
    HASH_ONLY = "hash_only"            # replace with hash-based placeholder


@dataclass(frozen=True)
class CategorySpec:
    name: Category
    mode: GranularityMode
    description: str  # used in summary output


CATEGORY_SPECS: dict[Category, CategorySpec] = {
    Category.CREDENTIAL: CategorySpec(
        Category.CREDENTIAL,
        GranularityMode.FULL,
        "Credential value (token, key, password, cookie)",
    ),
    Category.INTERNAL_URL: CategorySpec(
        Category.INTERNAL_URL,
        GranularityMode.URL_STRUCTURED,
        "Internal URL (host masked, path structure preserved)",
    ),
    Category.INTERNAL_IP: CategorySpec(
        Category.INTERNAL_IP,
        GranularityMode.FULL,
        "Internal IP address",
    ),
    Category.PII_EMAIL: CategorySpec(
        Category.PII_EMAIL,
        GranularityMode.FULL,
        "Email address",
    ),
    Category.PII_NAME: CategorySpec(
        Category.PII_NAME,
        GranularityMode.FULL,
        "Personally identifiable name",
    ),
    Category.USER_ID: CategorySpec(
        Category.USER_ID,
        GranularityMode.HASH_ONLY,
        "User / resource ID",
    ),
}


def get_spec(category: Category) -> CategorySpec:
    return CATEGORY_SPECS[category]
