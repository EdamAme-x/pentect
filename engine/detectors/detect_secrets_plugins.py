"""Wrap detect-secrets plugin regexes as a Pentect Detector.

Why this exists
===============
detect-secrets ships a curated, well-maintained set of regexes for
well-known third-party credentials (Stripe, Twilio, SendGrid, Discord,
private keys, Basic Auth, Azure Storage, IBM Cloud IAM, ...). The
upstream project tracks new token formats as vendors introduce them, so
borrowing those regexes lets Pentect cover patterns we would otherwise
hand-roll one by one.

We deliberately use *just* the plugin classes' regex denylists -- not
the full detect-secrets pipeline -- so this stays a thin layer:
    1. instantiate each plugin
    2. iterate its compiled denylist regexes against the input
    3. emit Pentect Spans

We keep the set of plugins small and conservative on purpose. Plugins
like high_entropy_strings.* and keyword.* are noisy on real HARs (they
fire on placeholder hashes, base64-encoded image data, etc.), and
verification (the .verify_secret hook) is intentionally not used so we
never make outbound HTTP calls during masking.
"""
from __future__ import annotations

from typing import Iterable

from engine.categories import Category
from engine.detectors.base import Span


def _build_plugin_regexes() -> list[tuple[str, "re.Pattern[str]"]]:
    """Collect (label, compiled-regex) pairs from selected detect-secrets plugins."""
    out: list[tuple[str, "re.Pattern[str]"]] = []

    try:
        from detect_secrets.plugins.stripe import StripeDetector
        from detect_secrets.plugins.twilio import TwilioKeyDetector
        from detect_secrets.plugins.openai import OpenAIDetector
        from detect_secrets.plugins.sendgrid import SendGridDetector
        from detect_secrets.plugins.mailchimp import MailchimpDetector
        from detect_secrets.plugins.discord import DiscordBotTokenDetector
        from detect_secrets.plugins.basic_auth import BasicAuthDetector
        from detect_secrets.plugins.azure_storage_key import AzureStorageKeyDetector
        from detect_secrets.plugins.npm import NpmDetector
        from detect_secrets.plugins.pypi_token import PypiTokenDetector
        from detect_secrets.plugins.square_oauth import SquareOAuthDetector
        from detect_secrets.plugins.telegram_token import TelegramBotTokenDetector
    except ImportError as e:  # pragma: no cover
        raise RuntimeError(
            "detect-secrets is not installed. Install with: pip install detect-secrets"
        ) from e

    # Pentect already covers JWT, AWS, GitHub PAT, Slack and Google API key in
    # engine/detectors/rule.py, so we skip those plugins to avoid duplicate
    # spans (the merger would dedupe, but no point doing the work twice).
    detector_classes = [
        StripeDetector,
        TwilioKeyDetector,
        OpenAIDetector,
        SendGridDetector,
        MailchimpDetector,
        DiscordBotTokenDetector,
        # PrivateKeyDetector intentionally omitted: it matches the
        # `-----BEGIN ... PRIVATE KEY-----` armor line, which is a
        # public format marker and contains no secret bytes. Pentect's
        # SeedPhraseDetector masks the base64 *body* of the block
        # instead, leaving the BEGIN/END lines readable so the masked
        # output still says "this was a private key".
        BasicAuthDetector,
        AzureStorageKeyDetector,
        NpmDetector,
        PypiTokenDetector,
        SquareOAuthDetector,
        TelegramBotTokenDetector,
    ]

    for cls in detector_classes:
        inst = cls()
        secret_type = getattr(inst, "secret_type", cls.__name__)
        for regex in inst.denylist:
            out.append((str(secret_type), regex))
    return out


class DetectSecretsPluginDetector:
    """Run detect-secrets plugin regexes against arbitrary text.

    Emits CREDENTIAL spans. The match is taken as the full regex match span
    rather than a particular capture group, since detect-secrets plugins
    aren't all written with capture-group semantics in mind. For BasicAuth
    that means the whole `://user:pass@` chunk gets masked, which is
    actually what we want -- the user part is also sensitive in pentest
    traces.
    """

    name = "detect_secrets"

    def __init__(self) -> None:
        self._regexes = _build_plugin_regexes()

    def detect(self, text: str) -> list[Span]:
        out: list[Span] = []
        for _label, regex in self._regexes:
            for m in regex.finditer(text):
                out.append(
                    Span(
                        start=m.start(),
                        end=m.end(),
                        category=Category.CREDENTIAL,
                        source=self.name,
                    )
                )
        return out

    def detect_batch(self, texts: Iterable[str]) -> list[list[Span]]:
        return [self.detect(t) for t in texts]
