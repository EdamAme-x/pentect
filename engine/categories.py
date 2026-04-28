"""Category definitions and granularity modes (minimal PoC set)."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Category(str, Enum):
    CREDENTIAL = "CREDENTIAL"
    INTERNAL_URL = "INTERNAL_URL"
    INTERNAL_IP = "INTERNAL_IP"
    EXTERNAL_IP = "EXTERNAL_IP"
    PII_EMAIL = "PII_EMAIL"
    PII_NAME = "PII_NAME"
    USER_ID = "USER_ID"
    RESOURCE_ID = "RESOURCE_ID"


class GranularityMode(str, Enum):
    FULL = "full"                      # replace entire value with one placeholder
    URL_STRUCTURED = "url_structured"  # mask host + trailing ID, keep path structure
    EMAIL_LOCAL = "email_local"        # mask local part only, keep domain readable
    EMAIL_SPLIT_HASH = "email_split_hash"  # hash local and domain independently
    HASH_ONLY = "hash_only"            # replace with hash-based placeholder
    CREDENTIAL_PREFIX = "credential_prefix"  # keep known token prefix (AIza, sk-, ...) and mask the rest


@dataclass(frozen=True)
class CategorySpec:
    name: Category
    mode: GranularityMode
    description: str  # used in summary output


CATEGORY_SPECS: dict[Category, CategorySpec] = {
    Category.CREDENTIAL: CategorySpec(
        Category.CREDENTIAL,
        GranularityMode.CREDENTIAL_PREFIX,
        "Credential value (well-known prefix kept, secret part masked)",
    ),
    Category.INTERNAL_URL: CategorySpec(
        Category.INTERNAL_URL,
        GranularityMode.URL_STRUCTURED,
        "Internal URL (host masked, path structure preserved)",
    ),
    Category.INTERNAL_IP: CategorySpec(
        Category.INTERNAL_IP,
        GranularityMode.FULL,
        "Internal IP address (RFC 1918 / loopback / link-local)",
    ),
    Category.EXTERNAL_IP: CategorySpec(
        Category.EXTERNAL_IP,
        GranularityMode.FULL,
        "External / public IP address",
    ),
    Category.PII_EMAIL: CategorySpec(
        Category.PII_EMAIL,
        GranularityMode.EMAIL_SPLIT_HASH,
        "Email (local and domain hashed independently)",
    ),
    Category.PII_NAME: CategorySpec(
        Category.PII_NAME,
        GranularityMode.FULL,
        "Personally identifiable name",
    ),
    Category.USER_ID: CategorySpec(
        Category.USER_ID,
        GranularityMode.HASH_ONLY,
        "User identifier (a person or account)",
    ),
    Category.RESOURCE_ID: CategorySpec(
        Category.RESOURCE_ID,
        GranularityMode.HASH_ONLY,
        "Resource identifier (issue, order, basket, product, ...)",
    ),
}


def get_spec(category: Category) -> CategorySpec:
    return CATEGORY_SPECS[category]
