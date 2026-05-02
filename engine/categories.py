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
    # Public account / project handle on a known platform (github, twitter,
    # keybase, etc.). NOT a credential — the platform domain stays readable
    # so "github.com/<<PII_HANDLE_xxx>>/<<PII_HANDLE_yyy>>" still tells the
    # reader this is an OSS link.
    PII_HANDLE = "PII_HANDLE"
    # "Looks like X, can't fully confirm" buckets. Used by detectors
    # that cast a wide net on shape/heuristics — the mask is reversible
    # via MaskResult.recover() so over-masking is cheap. The category
    # name carries our guess so the analyst can tell what kind of value
    # was redacted without having to recover it.
    #
    # LIKELY_CRYPTO_ADDRESS — Base58 / Bech32 / hex shape that matches
    #   a wallet-address pattern but lacks a strong protocol prefix
    #   (e.g. an unanchored 32-44 char Base58 run that *could* be a
    #   Solana / Cardano / NEAR address but is also valid as an opaque
    #   token from some other system).
    LIKELY_CRYPTO_ADDRESS = "LIKELY_CRYPTO_ADDRESS"
    # LIKELY_HASH — high-entropy hex / base64 of a length matching a
    #   well-known digest (md5, sha1, sha256, blake2). Could be a
    #   commit hash, file checksum, password digest, ETag, etc. Not
    #   confirmed to be a credential but identifies content / state.
    LIKELY_HASH = "LIKELY_HASH"
    # LIKELY_TOKEN — looks like a credential (length, charset, entropy)
    #   but doesn't match any known vendor regex (Stripe / AWS / etc.)
    #   and didn't appear under a credential-shaped key. Catch-all for
    #   "random-looking string in a place we don't trust".
    LIKELY_TOKEN = "LIKELY_TOKEN"
    # Static asset body (minified JS / CSS, base64 image, webfont).
    # The content is public-CDN material with effectively no leak risk
    # but is the bulk of HAR size and dominates detector runtime if
    # walked. We replace the whole body with one placeholder up front
    # and skip detection on it. Recoverable via MaskResult.recover()
    # like every other category.
    STATIC_ASSET = "STATIC_ASSET"


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
    Category.PII_HANDLE: CategorySpec(
        Category.PII_HANDLE,
        GranularityMode.HASH_ONLY,
        "Public account / project handle on a known platform",
    ),
    Category.LIKELY_CRYPTO_ADDRESS: CategorySpec(
        Category.LIKELY_CRYPTO_ADDRESS,
        GranularityMode.HASH_ONLY,
        "Looks like a wallet address (Base58 / Bech32 shape, unconfirmed)",
    ),
    Category.LIKELY_HASH: CategorySpec(
        Category.LIKELY_HASH,
        GranularityMode.HASH_ONLY,
        "Looks like a digest / hash (entropy + length matching md5/sha1/sha256)",
    ),
    Category.LIKELY_TOKEN: CategorySpec(
        Category.LIKELY_TOKEN,
        GranularityMode.HASH_ONLY,
        "Looks like a credential token; no specific vendor pattern matched",
    ),
    Category.STATIC_ASSET: CategorySpec(
        Category.STATIC_ASSET,
        GranularityMode.HASH_ONLY,
        "Static asset body (minified JS / CSS / image / font)",
    ),
}


def get_spec(category: Category) -> CategorySpec:
    return CATEGORY_SPECS[category]
