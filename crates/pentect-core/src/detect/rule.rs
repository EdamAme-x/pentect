use std::sync::LazyLock;

use super::pattern::{MatchContextPolicy, PatternMatchDetector, PatternSpec};
use super::validate::Validator;
use super::Detector;
use crate::model::*;
use crate::normalize::NormalizedView;

/// A data-form rule (e.g. a TOML pack entry) before its pattern is compiled.
pub type RuleSpec = PatternSpec;

/// Anchored vendor-token rules. High confidence and linear-time (no ReDoS), so
/// these bypass the entropy/profile uncertainty. The built-in set is just the
/// default pack — `from_specs` builds the same detector from loaded data.
#[derive(Clone)]
pub struct RuleDetector {
    inner: PatternMatchDetector,
}

static BUILTIN_RULE_DETECTOR: LazyLock<RuleDetector> = LazyLock::new(RuleDetector::build_builtin);

impl RuleDetector {
    /// Compile data-form rules into a detector; errors if any pattern is invalid.
    pub fn from_specs(specs: Vec<RuleSpec>) -> Result<Self, String> {
        Ok(Self {
            inner: PatternMatchDetector::from_specs(specs)?,
        })
    }

    pub fn builtin() -> Self {
        BUILTIN_RULE_DETECTOR.clone()
    }

    #[cfg(test)]
    fn labels(&self) -> impl Iterator<Item = &str> {
        self.inner.labels()
    }

    fn build_builtin() -> Self {
        use Category::{Endpoint, Identifier, Pii, Secret};
        use Confidence::{High, Low, Medium};
        // Conventions, so new rules stay consistent:
        // - charset order is upper, lower, digits, then extras `_-`, with `-`
        //   written last and unescaped: `[A-Za-z0-9_-]`. Hex is `[0-9a-fA-F]`.
        // - confidence is the pattern's collision-resistance, not vendor fame:
        //   High = a unique prefix/structure makes a match almost certainly the
        //   secret; Medium = a short prefix plus generic hex/charset that a
        //   non-secret could plausibly hit (e.g. Twilio's `AC`+32hex).
        // - labels are UPPER_SNAKE (asserted in tests) so they render cleanly.
        let table: &[(&str, Category, &str, Confidence)] = &[
            (r"AKIA[A-Z0-9]{16}", Secret, "AWS_AKID", High),
            (
                r"sk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_-]{20,}",
                Secret,
                "ANTHROPIC_API_KEY",
                High,
            ),
            (r"sk-[A-Za-z0-9_-]{20,}", Secret, "OPENAI_API_KEY", High),
            // Copy/paste, log wrapping, and markdown often insert whitespace
            // around the vendor delimiter. Keep this specific to the distinctive
            // OpenAI prefix rather than deleting arbitrary whitespace in tokens.
            (
                r"sk[ \t]+-[ \t]*[A-Za-z0-9_-]{20,}",
                Secret,
                "OPENAI_API_KEY",
                High,
            ),
            (r"rpa_[A-Za-z0-9]{24,}", Secret, "RUNPOD_API_KEY", High),
            (r"hf_[A-Za-z0-9]{30,}", Secret, "HUGGINGFACE_TOKEN", High),
            (r"xox[baprs]-[A-Za-z0-9-]{10,}", Secret, "SLACK_TOKEN", High),
            (
                r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
                Secret,
                "SLACK_WEBHOOK",
                High,
            ),
            (
                r"https://(?:discord|discordapp)\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{50,}",
                Secret,
                "DISCORD_WEBHOOK",
                High,
            ),
            (
                r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b",
                Secret,
                "TELEGRAM_BOT_TOKEN",
                High,
            ),
            (
                r"(sk|rk)_(live|test)_[A-Za-z0-9]{10,}",
                Secret,
                "STRIPE_SECRET_KEY",
                High,
            ),
            (r"AIza[A-Za-z0-9_-]{35}", Secret, "GOOGLE_API_KEY", High),
            (
                r"GOCSPX-[A-Za-z0-9_-]{28}",
                Secret,
                "GOOGLE_OAUTH_SECRET",
                High,
            ),
            (
                r"ya29\.[A-Za-z0-9_-]{20,}",
                Secret,
                "GOOGLE_OAUTH_TOKEN",
                High,
            ),
            // Fine-grained PAT; distinct format from the classic gh*_ family.
            (r"github_pat_[A-Za-z0-9_]{22,}", Secret, "GITHUB_PAT", High),
            // Classic GitHub token family (p/o/u/s/r) is one format, so one rule.
            (r"gh[oprsu]_[A-Za-z0-9]{36}", Secret, "GITHUB_TOKEN", High),
            (
                r"AC[0-9a-fA-F]{32}",
                Identifier,
                "TWILIO_ACCOUNT_SID",
                Medium,
            ),
            (
                r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
                Secret,
                "SENDGRID_KEY",
                High,
            ),
            (r"npm_[A-Za-z0-9]{36}", Secret, "NPM_TOKEN", High),
            // Domain is label(.label)*.tld, so consecutive/trailing dots and a
            // leading-dot domain don't match. TLD capped to bound the match.
            (
                r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}",
                Pii,
                "IDENTITY",
                Medium,
            ),
            // Cloud / DB secrets and network identifiers (pattern-only). The
            // prefix-anchored ones are near-zero false-positive; the connection
            // string masks the whole `scheme://user:pass@host` (credential incl).
            (
                r"do[opr]_v1_[a-f0-9]{64}",
                Secret,
                "DIGITALOCEAN_TOKEN",
                High,
            ),
            (
                r"shp(at|ca|pa|ss)_[a-fA-F0-9]{32}",
                Secret,
                "SHOPIFY_TOKEN",
                High,
            ),
            (
                r"(?:EAAA|sq0atp-|sq0csp-)[A-Za-z0-9_-]{22,60}",
                Secret,
                "SQUARE_TOKEN",
                Medium,
            ),
            (
                r"(?:key|pubkey)-[a-f0-9]{32}",
                Secret,
                "MAILGUN_API_KEY",
                Medium,
            ),
            (
                r#""private_key_id"[ \t]*:[ \t]*"[0-9a-f]{40}""#,
                Secret,
                "GCP_PRIVATE_KEY_ID",
                Medium,
            ),
            (
                r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b",
                Identifier,
                "MAC_ADDRESS",
                Medium,
            ),
            (
                r"\b(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}(?:/(?:3[0-2]|[12][0-9]|[0-9]))?\b",
                Endpoint,
                "IP_ADDRESS_V4",
                High,
            ),
            // Structural national IDs (no public checksum) — the regex encodes the
            // grammar; confidence reflects how distinctive it is. Higher false-
            // positive risk than the checksummed ones, kept lower-confidence.
            // Separators required: a bare 9-digit run is any number, not an ITIN.
            (
                r"\b9[0-9]{2}[- ](?:5[0-9]|6[0-5]|7[0-9]|8[0-8]|9[0-24-9])[- ][0-9]{4}\b",
                Identifier,
                "US_ITIN",
                Medium,
            ),
            (
                r"\b[0-9][ACDEFGHJKMNPQRTUVWXY][0-9ACDEFGHJKMNPQRTUVWXY][0-9][- ]?[ACDEFGHJKMNPQRTUVWXY][0-9ACDEFGHJKMNPQRTUVWXY][0-9][- ]?[ACDEFGHJKMNPQRTUVWXY][ACDEFGHJKMNPQRTUVWXY][0-9][0-9]\b",
                Pii,
                "US_MBI",
                Medium,
            ),
            // No checksum, so context-gated (multilingual keyword): a bare
            // letter+8-digits is any SKU.
            (
                r"(?i)(?:passport|pasaporte|passeport|passaporto|reisepass|パスポート|旅券)[^\n]{0,12}?\b[A-Z][0-9]{8}\b",
                Identifier,
                "US_PASSPORT",
                Low,
            ),
            (
                r"(?i)\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z][ -]?[0-9]{2}[ -]?[0-9]{2}[ -]?[0-9]{2}[ -]?[A-D]\b",
                Identifier,
                "UK_NINO",
                Medium,
            ),
            (
                r"\b[A-Za-z]{3}[AaBbCcFfGgHhJjLlPpTt][A-Za-z][0-9]{4}[A-Za-z]\b",
                Identifier,
                "IN_PAN",
                Medium,
            ),
            // No checksum (SWIFT has none), so context-gated: otherwise any 8-
            // letter uppercase word (WIDGETCO, ABCDEFGH) masks as a BIC.
            (
                r"(?i)(?:swift|bic)[^\n]{0,10}?\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
                Identifier,
                "SWIFT_BIC",
                Medium,
            ),
            // Uppercase country code + a digit-led body (no spaces, no (?i)) so
            // prose like "seed ..." or all-caps words don't match.
            (
                r"\b(?:AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|GB|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK|XI)[0-9]{2}[0-9A-Z]{4,10}\b",
                Identifier,
                "EU_VAT",
                Low,
            ),
            // Context-gated cloud secrets (the literal vendor word near the value).
            (
                r#"(?i)(?:datadog|dd[_-]?(?:api|app|application)[_-]?key|dd_client_token)[a-z0-9 ._\-"'=:>|?,]{0,30}\b(?:[a-f0-9]{32}|[a-f0-9]{40})\b"#,
                Secret,
                "DATADOG_API_KEY",
                Medium,
            ),
            (
                r#"(?i)postmark[a-z0-9 ._\-"'=:>|?,]{0,40}\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"#,
                Secret,
                "POSTMARK_SERVER_TOKEN",
                Medium,
            ),
            (
                r#"(?i)heroku[a-z0-9 ._\-"'=:>|?,]{0,40}\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"#,
                Secret,
                "HEROKU_API_KEY",
                Medium,
            ),
            // Phone: no checksum, so only the distinctive forms are enabled — an
            // International `+CC...` numbers are handled by PhoneDetector (the
            // libphonenumber crate, validated). This rule covers a NANP number
            // with real separators (so a bare 10-digit order number is not
            // masked) for the common no-country-code US case.
            (
                r"(?:\+?1[ .-])?\(?[2-9][0-9]{2}\)?[ .-][2-9][0-9]{2}[ .-][0-9]{4}",
                Pii,
                "PHONE_NANP",
                Medium,
            ),
            // URL (scheme required, so it doesn't match bare hostnames).
            (
                r#"(?i)\b(?:https?|ftp|ftps|wss?)://[^\s"'<>()]*[^\s"'<>().,;:!?]"#,
                Endpoint,
                "URL",
                Medium,
            ),
            // Context-gated like Presidio: a bare number/ID only fires next to its
            // keyword, so these don't flood. The match includes the keyword.
            (
                r"(?i)(?:\bacc(?:ount|t)\b|konto|compte|cuenta|口座)[^\n]{0,15}?\b[0-9]{8,17}\b",
                Identifier,
                "US_BANK_ACCOUNT",
                Low,
            ),
            (
                r"(?i)(?:driver'?s?\s*licen[sc]e|\bDLN?\b|führerschein|permis de conduire|運転免許)[^\n]{0,15}?\b[A-Z0-9]{5,13}\b",
                Identifier,
                "US_DRIVER_LICENSE",
                Low,
            ),
            // Country long-tail (Presidio parity). Distinctive formats run
            // context-free; ambiguous shapes (passports, plates, voter/UEN) are
            // context-gated so a bare token doesn't mask.
            (
                r"(?i)\b[A-Z]{1,2}[0-9][A-Z0-9]? ?[0-9][A-Z]{2}\b",
                Pii,
                "UK_POSTCODE",
                Medium,
            ),
            (
                r"\b[A-Z9]{5}[0-9]{6}[A-Z9]{2}[0-9][A-Z]{2}\b",
                Identifier,
                "UK_DRIVING_LICENCE",
                Medium,
            ),
            (
                r"(?i)(?:reg|plate|vehicle)[^\n]{0,15}?\b[A-Z]{2}[0-9]{2} ?[A-Z]{3}\b",
                Identifier,
                "UK_VEHICLE_REGISTRATION",
                Low,
            ),
            (
                r"(?i)(?:passport|pasaporte|passeport|passaporto|reisepass|パスポート|旅券)[^\n]{0,15}?\b[0-9]{9}\b",
                Identifier,
                "UK_PASSPORT",
                Low,
            ),
            (
                r"(?i)(?:passport|pasaporte|passeport|passaporto|reisepass|パスポート|旅券)[^\n]{0,15}?\b[A-Z]{3}[0-9]{6}[A-Z]?\b",
                Identifier,
                "ES_PASSPORT",
                Low,
            ),
            (
                r"(?i)(?:passport|pasaporte|passeport|passaporto|reisepass|パスポート|旅券)[^\n]{0,15}?\b[A-Z]{2}[0-9]{7}\b",
                Identifier,
                "IT_PASSPORT",
                Low,
            ),
            (
                r"(?i)(?:voter|epic)[^\n]{0,15}?\b[A-Z]{3}[0-9]{7}\b",
                Identifier,
                "IN_VOTER",
                Low,
            ),
            (
                r"(?i)(?:passport|pasaporte|passeport|passaporto|reisepass|パスポート|旅券)[^\n]{0,15}?\b[A-Z][0-9]{7}\b",
                Identifier,
                "IN_PASSPORT",
                Low,
            ),
            (
                r"(?i)(?:vehicle|registration|reg)[^\n]{0,15}?\b[A-Z]{2}[ -]?[0-9]{1,2}[ -]?[A-Z]{1,3}[ -]?[0-9]{4}\b",
                Identifier,
                "IN_VEHICLE_REGISTRATION",
                Low,
            ),
            (
                r"(?i)uen[^\n]{0,12}?\b(?:[0-9]{8,9}[A-Z]|[STR][0-9]{2}[A-Z]{2}[0-9]{4}[A-Z])\b",
                Identifier,
                "SG_UEN",
                Low,
            ),
        ];
        use Validator as V;
        // Checksum-gated detectors: a permissive pattern finds candidates, the
        // validator (Luhn, mod-97, Verhoeff, weighted mod-N, ...) confirms them.
        // This is how we match/exceed Presidio's recognizers deterministically.
        #[rustfmt::skip]
        let checked: &[(&str, Category, &str, Confidence, Validator)] = &[
            // Separator-formatted cards (CardDetector handles contiguous digits;
            // these handle the common "4242 4242 4242 4242" grouping). Luhn-gated.
            (r"\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}\b", Pii, "CARD", High, V::Luhn),
            (r"\b\d{4}[ -]\d{6}[ -]\d{5}\b", Pii, "CARD", High, V::Luhn),
            (r"\b\d{4}[ -]\d{6}[ -]\d{4}\b", Pii, "CARD", High, V::Luhn),
            (r"SK[0-9a-fA-F]{32}", Secret, "TWILIO_API_KEY", Medium, V::TwilioApiKey),
            (r"\b[12][0-9]{3}[- ]?[0-9]{3}[- ]?[0-9]{3}\b", Identifier, "US_NPI", High, V::UsNpi),
            (r"\bIT[0-9]{11}\b", Identifier, "IT_VAT_CODE", High, V::Luhn),
            (r"(?i)social insurance[^\n]{0,15}?\b[1-79]\d{2}[ -]?\d{3}[ -]?\d{3}\b", Pii, "CA_SIN", High, V::CaSin),
            (r"\b[0123678][0-9]{8}\b", Identifier, "US_ABA_ROUTING", High, V::AbaRouting),
            (r"\b[ABCDEFGHJKLMPRSTUX][A-Z9][0-9]{7}\b", Identifier, "US_DEA_NUMBER", High, V::UsDea),
            (r"(?i)\b[A-Z]{2}[0-9]{2}[ ]?[A-Z0-9]{4}(?:[ ]?[A-Z0-9]{4}){1,6}[ ]?[A-Z0-9]{0,3}\b", Identifier, "IBAN_CODE", High, V::IbanMod97),
            (r"(?i)nhs[^\n]{0,12}?\b[0-9]{3}[ -]?[0-9]{3}[ -]?[0-9]{4}\b", Identifier, "UK_NHS", High, V::UkNhs),
            (r"(?i)pesel[^\n]{0,12}?\b[0-9]{11}\b", Identifier, "PL_PESEL", High, V::PlPesel),
            (r"(?i)(?:tfn|tax file)[^\n]{0,12}?\b\d{3}[ -]?\d{3}[ -]?\d{3}\b", Pii, "AU_TFN", High, V::AuTfn),
            (r"\b\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[ -]?[1-8]\d{6}\b", Pii, "KR_RRN", High, V::KrRrn),
            (r"(?i)\b[0-9]{8}[ -]?[A-Z]\b", Identifier, "ES_DNI_NIF", High, V::EsNif),
            (r"(?i)\b[XYZ][ -]?[0-9]{7}[ -]?[A-Z]\b", Identifier, "ES_NIE", High, V::EsNie),
            (r"\b[0-9]{2}[ ]?[0-9]{3}[ ]?[0-9]{3}[ ]?[0-9]{3}\b", Identifier, "DE_TAX_ID", High, V::DeTaxId),
            (r"(?i)\bbsn\b[^\n]{0,12}?\b[0-9]{8,9}\b", Identifier, "NL_BSN", Medium, V::NlBsn),
            (r"(?i)\b[STFGM][0-9]{7}[A-Z]\b", Pii, "SG_NRIC_FIN", High, V::SgNricFin),
            (r"\b\d{2}[ ]?\d{3}[ ]?\d{3}[ ]?\d{3}\b", Identifier, "AU_ABN", High, V::AuAbn),
            (r"(?i)medicare[^\n]{0,15}?\b[2-6]\d{3}[ ]?\d{5}[ ]?\d\b", Pii, "AU_MEDICARE", High, V::AuMedicare),
            (r"\b[2-9][0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}\b", Pii, "IN_AADHAAR", High, V::Verhoeff),
            (r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b", Pii, "BR_CPF", High, V::BrCpf),
            (r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b", Identifier, "BR_CNPJ", High, V::BrCnpj),
            (r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", Identifier, "BTC_ADDRESS", High, V::BtcAddress),
            (r"\b[LM3][a-km-zA-HJ-NP-Z1-9]{25,34}\b", Identifier, "LTC_ADDRESS", High, V::LtcAddress),
            (r"\br[rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz]{24,34}\b", Identifier, "XRP_ADDRESS", High, V::XrpAddress),
            (r"\b[5KL][a-km-zA-HJ-NP-Z1-9]{50,51}\b", Secret, "CRYPTO_PRIVATE_KEY_WIF", High, V::Wif),
            (r"\b[0-8][0-9]{2}[- ][0-9]{2}[- ][0-9]{4}\b", Pii, "US_SSN", Medium, V::UsSsn),
            (r"\bbc1[02-9ac-hj-np-z]{6,87}\b", Identifier, "BTC_ADDRESS_BECH32", High, V::BtcBech32),
            (r"\b0x[0-9a-fA-F]{40}\b", Identifier, "ETH_ADDRESS", High, V::EthAddress),
            (r"\b[0-9]{6}[-+A-Y][0-9]{3}[0-9A-Y]\b", Identifier, "FI_HETU", High, V::FiHetu),
            (r"(?i)\b[A-Z]{6}[0-9A-Z]{2}[A-Z][0-9A-Z]{2}[A-Z][0-9A-Z]{3}[A-Z]\b", Identifier, "IT_FISCAL_CODE", High, V::ItFiscalCode),
            (r"\b[12][0-9]{4}(?:[0-9]{2}|2[AB])[0-9]{8}\b", Identifier, "FR_NIR_INSEE", High, V::FrNir),
            (r"(?i)(?:acn|company number)[^\n]{0,12}?\b\d{3}[ ]?\d{3}[ ]?\d{3}\b", Identifier, "AU_ACN", High, V::AuAcn),
            (r"\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][0-9A-Z]Z[0-9A-Z]\b", Identifier, "IN_GSTIN", High, V::InGstin),
            // Connection strings are credential-bearing only when the userinfo
            // is concrete. Docs/templates such as `[user[:password]@]` and
            // `<password>` are filtered by the validator.
            (r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?)://[^\s:/@]+:[^\s:/@]+@[^\s/?#]+", Secret, "DB_CONNECTION_STRING", High, V::DbConnectionString),
        ];
        #[rustfmt::skip]
        let captured: &[(&str, Category, &str, Confidence, usize, Validator)] = &[
            // JWT compact serialization has exactly three base64url segments.
            // JWE compact serialization has five; do not mask the first three
            // segments as a JWT just because the protected header starts `eyJ`.
            (r#"(?i)(?:^|[^A-Za-z0-9_.-])(eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*)(?:$|[^A-Za-z0-9_.-])"#, Secret, "JWT_SECRET", High, 1, V::None),
            // Session/JWT-like values need context. A bare aaa.bbb.ccc is common
            // test/noise; a long three-segment token after session/jwt/cookie is
            // credential-bearing even if the header is opaque or not JSON.
            (r#"(?i)\b(?:session|sid|jwt|cookie|auth[-_ ]?token|access[-_ ]?token|refresh[-_ ]?token)\b[^\r\n]{0,16}?(?:=|:)[ \t'"]{0,3}([A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,})(?:$|[\s"',;)])"#, Secret, "SESSION_TOKEN", Medium, 1, V::None),
            // RFC 7617 Basic credentials use token68 after the `Basic` scheme.
            // Require nearby Authorization/auth wording so prose like
            // `Basic docs` or unrelated base64 samples do not become secrets.
            (r#"(?i)\b(?:proxy-authorization|authorization|auth)\b[^\r\n]{0,40}?\bbasic[ \t]+([A-Za-z0-9+/]{8,}={0,2})(?:$|[\s"',;)])"#, Secret, "BASIC_AUTH", Medium, 1, V::BasicAuthToken68),
            // The same RFC 7617 scheme also appears as a standalone header
            // value in structured YAML/JSON. The validator must decode a
            // concrete `user:password` pair, so placeholder/prose token68 stays
            // negative.
            (r#"(?i)(?:^|[^A-Za-z0-9+/=])basic[ \t]+([A-Za-z0-9+/]{8,}={0,2})(?:$|[\s"',;)])"#, Secret, "BASIC_AUTH", Medium, 1, V::BasicAuthToken68),
            // RFC 6750 bearer credentials can appear as standalone auth-scheme
            // lines in OpenAPI/YAML examples. The validator rejects prose and
            // placeholder token names.
            (r#"(?i)(?:^|[^A-Za-z0-9_-])bearer[ \t]+([A-Za-z0-9._~+/=-]{20,})(?:$|[\s"',;)])"#, Secret, "BEARER_TOKEN", Medium, 1, V::BearerToken),
            // SQL DDL password clauses are grammar-level credential material
            // across PostgreSQL/MySQL/Oracle/SQL Server style statements. Split
            // quoted/bare values so only the password bytes are masked.
            (r#"(?i)\b(?:create|alter)\s+(?:user|role|login)\b[^\r\n;]{0,180}?\b(?:identified\s+(?:with\s+(?:'[^'\r\n]{1,64}'|[A-Za-z0-9_]+)\s+)?(?:by|as)|password)\s*=?\s*'([^'\r\n]{1,160})'"#, Secret, "SQL_PASSWORD", Medium, 1, V::SqlPasswordValue),
            (r#"(?i)\b(?:create|alter)\s+(?:user|role|login)\b[^\r\n;]{0,180}?\b(?:identified\s+(?:with\s+(?:"[^"\r\n]{1,64}"|[A-Za-z0-9_]+)\s+)?(?:by|as)|password)\s*=?\s*"([^"\r\n]{1,160})""#, Secret, "SQL_PASSWORD", Medium, 1, V::SqlPasswordValue),
            (r#"(?i)\b(?:create|alter)\s+(?:user|role|login)\b[^\r\n;]{0,180}?\b(?:identified\s+(?:with\s+[A-Za-z0-9_]+\s+)?(?:by|as)|password)\s*=?\s*([^\s;,)'"`]{1,160})(?:$|[\s;,)])"#, Secret, "SQL_PASSWORD", Medium, 1, V::SqlPasswordValue),
            // Preserve path structure for debugging, but hide the local account
            // segment that frequently leaks in stack traces and tool output.
            (r#"(?i)\bAccountKey\b[ \t]*=[ \t]*([A-Za-z0-9+/=]{40,})(?:;|$|[\s"',)])"#, Secret, "AZURE_STORAGE_ACCOUNT_KEY", High, 1, V::None),
            (r#"(?i)\bclient[-_]?key[-_]?data\b[ \t]*:[ \t]*['"]?([A-Za-z0-9+/=]{40,})['"]?(?:$|[\s"',;)])"#, Secret, "KUBE_CLIENT_KEY_DATA", High, 1, V::None),
            (r#"(?i)(?:^|[^A-Za-z0-9_:.])((?:[0-9A-F]{0,4}:){2,}[0-9A-F]{0,4}(?:%[0-9A-Za-z]+)?(?:/(?:12[0-8]|1[01][0-9]|[1-9]?[0-9]))?)(?:$|[^A-Za-z0-9_:.])"#, Endpoint, "IP_ADDRESS_V6", High, 1, V::Ipv6),
            (r#"(?i)\b[A-Z]:[\\/]+Users[\\/]+([^\\/\s:\r\n"<>|?*]{1,64})(?:[\\/]|$|[\s"',;)])"#, Pii, "LOCAL_USERNAME", Medium, 1, V::LocalUsername),
            (r#"(?i)(?:^|[\s"'=(:])/(?:home|Users|var/home|export/home)/([^/\s\r\n"']{1,64})(?:/|$|[\s"',;)])"#, Pii, "LOCAL_USERNAME", Medium, 1, V::LocalUsername),
            (r#"(?i)(?:^|[\s"'=(:])~([^/\s\r\n"']{1,64})(?:/|$|[\s"',;)])"#, Pii, "LOCAL_USERNAME", Medium, 1, V::LocalUsername),
            (r#"(?i)(?:^|[\s"'=(:])/[a-z]/Users/([^/\s\r\n"']{1,64})(?:/|$|[\s"',;)])"#, Pii, "LOCAL_USERNAME", Medium, 1, V::LocalUsername),
            (r#"(?i)(?:^|[\s"'=(:])/mnt/[a-z]/Users/([^/\s\r\n"']{1,64})(?:/|$|[\s"',;)])"#, Pii, "LOCAL_USERNAME", Medium, 1, V::LocalUsername),
            // Avoid slicing the 12-digit tail out of UUIDs / hashes while still
            // masking a standalone My Number. Rust regex has no look-around, so
            // capture only the candidate and keep the separators outside.
            (r#"(?i)(?:^|[\s"'=:(,;])([0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4})(?:$|[\s"',;.)\]])"#, Pii, "JP_MY_NUMBER", High, 1, V::JpMyNumber),
        ];
        let specs = table
            .iter()
            .map(|&(pattern, category, label, confidence)| RuleSpec {
                pattern: pattern.to_string(),
                category,
                label: label.to_string(),
                confidence,
                validator: V::None,
                context: builtin_context_policy(label),
                capture: 0,
                prefilter: builtin_prefilter(label, pattern),
            })
            .chain(
                checked.iter().map(
                    |&(pattern, category, label, confidence, validator)| RuleSpec {
                        pattern: pattern.to_string(),
                        category,
                        label: label.to_string(),
                        confidence,
                        validator,
                        context: builtin_context_policy(label),
                        capture: 0,
                        prefilter: builtin_prefilter(label, pattern),
                    },
                ),
            )
            .chain(captured.iter().map(
                |&(pattern, category, label, confidence, capture, validator)| RuleSpec {
                    pattern: pattern.to_string(),
                    category,
                    label: label.to_string(),
                    confidence,
                    validator,
                    context: builtin_context_policy(label),
                    capture,
                    prefilter: builtin_prefilter(label, pattern),
                },
            ))
            .collect();
        Self::from_specs(specs).expect("builtin regexes compile")
    }
}

impl Detector for RuleDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        self.inner.detect(view)
    }
}

fn builtin_prefilter(label: &str, pattern: &str) -> Vec<String> {
    let literals: &[&str] = match label {
        "JWT_SECRET" => &["eyJ"],
        "AWS_AKID" => &["AKIA"],
        "ANTHROPIC_API_KEY" => &["sk-ant-"],
        "OPENAI_API_KEY" if pattern.contains(r"[ \t]+") => &["sk ", "sk\t"],
        "OPENAI_API_KEY" => &["sk-"],
        "RUNPOD_API_KEY" => &["rpa_"],
        "HUGGINGFACE_TOKEN" => &["hf_"],
        "SLACK_TOKEN" => &["xox"],
        "SLACK_WEBHOOK" => &["hooks.slack.com/services/"],
        "DISCORD_WEBHOOK" => &["discord.com/api/webhooks/", "discordapp.com/api/webhooks/"],
        "STRIPE_SECRET_KEY" => &["_live_", "_test_"],
        "GOOGLE_API_KEY" => &["AIza"],
        "GOOGLE_OAUTH_SECRET" => &["GOCSPX-"],
        "GOOGLE_OAUTH_TOKEN" => &["ya29."],
        "GITHUB_PAT" => &["github_pat_"],
        "GITHUB_TOKEN" => &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        "SENDGRID_KEY" => &["SG."],
        "NPM_TOKEN" => &["npm_"],
        "DIGITALOCEAN_TOKEN" => &["dop_v1_", "doo_v1_", "dor_v1_"],
        "SHOPIFY_TOKEN" => &["shpat_", "shpca_", "shppa_", "shpss_"],
        "SQUARE_TOKEN" => &["EAAA", "sq0atp-", "sq0csp-"],
        "GCP_PRIVATE_KEY_ID" => &["private_key_id"],
        "DATADOG_API_KEY" => &[
            "datadog",
            "dd_api",
            "dd-api",
            "dd_app",
            "dd-app",
            "dd_client_token",
        ],
        "POSTMARK_SERVER_TOKEN" => &["postmark"],
        "HEROKU_API_KEY" => &["heroku"],
        "SESSION_TOKEN" => &[
            "session", "sid", "jwt", "cookie", "auth", "access", "refresh",
        ],
        "BASIC_AUTH" => &["Basic ", "Basic\t"],
        "DB_CONNECTION_STRING" => &[
            "postgres://",
            "postgresql://",
            "mysql://",
            "mongodb://",
            "mongodb+srv://",
            "redis://",
            "rediss://",
            "amqp://",
            "amqps://",
        ],
        "URL" => &["://"],
        "US_PASSPORT" | "UK_PASSPORT" | "ES_PASSPORT" | "IT_PASSPORT" | "IN_PASSPORT" => &[
            "passport",
            "pasaporte",
            "passeport",
            "passaporto",
            "reisepass",
            "パスポート",
            "旅券",
        ],
        "SWIFT_BIC" => &["swift", "bic"],
        "CA_SIN" => &["social insurance"],
        "UK_NHS" => &["nhs"],
        "PL_PESEL" => &["pesel"],
        "AU_TFN" => &["tfn", "tax file"],
        "NL_BSN" => &["bsn"],
        "AU_MEDICARE" => &["medicare"],
        "AU_ACN" => &["acn", "company number"],
        "US_BANK_ACCOUNT" => &[
            "account", "acct", "acc", "konto", "compte", "cuenta", "口座",
        ],
        "IN_VOTER" => &["voter", "epic"],
        "SG_UEN" => &["uen"],
        "AZURE_STORAGE_ACCOUNT_KEY" => &["AccountKey"],
        "KUBE_CLIENT_KEY_DATA" => &[
            "clientkeydata",
            "client-keydata",
            "client_keydata",
            "clientkey-data",
            "clientkey_data",
            "client-key-data",
            "client-key_data",
            "client_key-data",
            "client_key_data",
        ],
        _ => &[],
    };
    literals.iter().map(|s| (*s).to_string()).collect()
}

fn builtin_context_policy(label: &str) -> MatchContextPolicy {
    match label {
        // The `EAAA...` Square prefix collides with OpenSSH public-key base64.
        // Keep the vendor rule itself, but reject matches on lines already
        // shaped as public SSH keys. Private key material is handled elsewhere.
        "SQUARE_TOKEN" => MatchContextPolicy::NotPublicSshKeyLine,
        _ => MatchContextPolicy::Any,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::region;
    use regex::Regex;

    // Small labelled recall corpus: each vendor secret must be detected under
    // the right label. Samples are split with concat! so the provider prefix and
    // body are separate literals (no contiguous secret in source, which would
    // trip GitHub push protection); the joined value still matches the rule.
    #[test]
    fn vendor_recall_corpus() {
        let cases: &[(&str, &str)] = &[
            ("AKIAIOSFODNN7EXAMPLE", "AWS_AKID"),
            (concat!("sk", "-ABCDEFGHIJKLMNOPQRSTUVWX"), "OPENAI_API_KEY"),
            (
                concat!("sk", " -ABCDEFGHIJKLMNOPQRSTUVWX"),
                "OPENAI_API_KEY",
            ),
            (
                concat!("rpa", "_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"),
                "RUNPOD_API_KEY",
            ),
            (
                concat!("sk-ant-api03-", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"),
                "ANTHROPIC_API_KEY",
            ),
            (
                concat!("hf", "_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"),
                "HUGGINGFACE_TOKEN",
            ),
            (
                concat!("ghp", "_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
                "GITHUB_TOKEN",
            ),
            (
                concat!("github", "_pat_11ABCDEFG0aBcDeFgHiJkLmNoPqRsTuVwXyZ"),
                "GITHUB_PAT",
            ),
            (
                concat!("ghs", "_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
                "GITHUB_TOKEN",
            ),
            (
                concat!("sk", "_live_ABCDEFGHIJ1234567890"),
                "STRIPE_SECRET_KEY",
            ),
            (
                concat!("AIza", "SyA1234567890abcdefghijklmnopqrstuv0"),
                "GOOGLE_API_KEY",
            ),
            (
                concat!("GOCSPX", "-abcdefghijklmnopqrstuvwxyz12"),
                "GOOGLE_OAUTH_SECRET",
            ),
            (
                concat!("ya29", ".A0ARrdaMabcdefghijklmnopqrstuvwxyz"),
                "GOOGLE_OAUTH_TOKEN",
            ),
            (
                concat!("SK", "abcdef0123456789abcdef0123456789"),
                "TWILIO_API_KEY",
            ),
            (
                concat!(
                    "SG",
                    ".abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
                ),
                "SENDGRID_KEY",
            ),
            (
                concat!("npm", "_abcdefghijklmnopqrstuvwxyz0123456789"),
                "NPM_TOKEN",
            ),
            (
                concat!(
                    "https://hooks.slack.com/services/",
                    "T00000000/B00000000/abcdEFGH"
                ),
                "SLACK_WEBHOOK",
            ),
            (
                concat!(
                    "https://discord.com/api/webhooks/123456789012345678/",
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789AB"
                ),
                "DISCORD_WEBHOOK",
            ),
            (
                concat!("1234567890:", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"),
                "TELEGRAM_BOT_TOKEN",
            ),
            (
                concat!(
                    "dop",
                    "_v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ),
                "DIGITALOCEAN_TOKEN",
            ),
            (
                concat!("shp", "at_0123456789abcdef0123456789abcdef"),
                "SHOPIFY_TOKEN",
            ),
            (
                "postgresql://admin:s3cr3t@db.host:5432/sales",
                "DB_CONNECTION_STRING",
            ),
            ("00:1A:2B:3C:4D:5E", "MAC_ADDRESS"),
            ("192.168.1.1", "IP_ADDRESS_V4"),
            ("(415) 555-0132", "PHONE_NANP"),
            // Multilingual context keywords (Presidio supports multiple languages).
            ("パスポート C12345678", "US_PASSPORT"),
            ("Konto 12345678 prüfen", "US_BANK_ACCOUNT"),
        ];
        let det = RuleDetector::builtin();
        for (sample, label) in cases {
            let reg = region(sample);
            let v = NormalizedView::build(&reg, sample);
            let spans = det.detect(&v);
            assert!(
                spans.iter().any(|s| &s.label == label),
                "{sample} should detect {label}, got {:?}",
                spans.iter().map(|s| &s.label).collect::<Vec<_>>()
            );
        }
    }

    // Every label must be UPPER_SNAKE so it renders into a well-formed
    // `<<LABEL_hash>>` placeholder; a new rule can't smuggle in a bad label.
    #[test]
    fn rule_labels_are_upper_snake() {
        let label_re = Regex::new(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$").unwrap();
        for label in RuleDetector::builtin().labels() {
            assert!(label_re.is_match(label), "bad label: {label}");
        }
    }

    // The tightened email rule must reject malformed domains while still
    // matching ordinary addresses.
    #[test]
    fn email_rule_rejects_malformed_domains() {
        let det = RuleDetector::builtin();
        let hits = |s: &str| {
            let reg = region(s);
            let v = NormalizedView::build(&reg, s);
            det.detect(&v).iter().any(|sp| sp.label == "IDENTITY")
        };
        assert!(hits("alice@example.com"));
        assert!(hits("a@b.co.uk"));
        assert!(!hits("alice@.com"));
        assert!(!hits("alice@example."));
    }

    #[test]
    fn square_rule_ignores_public_ssh_key_context() {
        let det = RuleDetector::builtin();
        let has_square = |s: &str| {
            let reg = region(s);
            let v = NormalizedView::build(&reg, s);
            det.detect(&v).iter().any(|sp| sp.label == "SQUARE_TOKEN")
        };
        assert!(has_square(
            "token=EAAAabcdefghijklmnopqrstuvwxyzABCDEF123456"
        ));
        assert!(!has_square(
            r#"{"key":"ssh-rsa AAAAB3NzaC1yc2EAAAabcdefghijklmnopqrstuvwxyzABCDEF123456"}"#
        ));
    }

    #[test]
    fn url_rule_keeps_sentence_punctuation_literal() {
        let det = RuleDetector::builtin();
        let raw = "see https://example.com/api/issues/1234. next";
        let spans = det.detect(&NormalizedView::build(&region(raw), raw));
        let Some(span) = spans.iter().find(|s| s.label == "URL") else {
            panic!("URL should be detected: {spans:?}");
        };
        assert_eq!(
            &raw[span.range.start..span.range.end],
            "https://example.com/api/issues/1234"
        );
    }

    #[test]
    fn db_connection_string_rejects_uri_templates() {
        let det = RuleDetector::builtin();
        let labels = |s: &str| {
            det.detect(&NormalizedView::build(&region(s), s))
                .into_iter()
                .map(|span| span.label)
                .collect::<Vec<_>>()
        };
        for raw in [
            "postgresql://[user[:password]@][host][:port][",
            "mongodb://username:<password>@cluster0.example.com:27017",
            "redis://***:***@localhost:6379",
        ] {
            assert!(
                labels(raw)
                    .iter()
                    .all(|label| label != "DB_CONNECTION_STRING"),
                "{raw}: {:?}",
                labels(raw)
            );
        }
        assert!(labels("postgresql://admin:s3cr3t@db.host:5432/sales")
            .iter()
            .any(|label| label == "DB_CONNECTION_STRING"));
    }

    #[test]
    fn captured_context_rules_mask_selected_values_without_masking_counters() {
        let det = RuleDetector::builtin();
        let labels = |s: &str| {
            let reg = region(s);
            let v = NormalizedView::build(&reg, s);
            det.detect(&v)
                .iter()
                .map(|sp| sp.label.clone())
                .collect::<Vec<_>>()
        };
        let has = |text: &str, label: &str| labels(text).iter().any(|got| got == label);
        assert!(has(
            "cookie session=abcdefghijkl.mnopqrstuvwxyz.ABCDEFGHIJKLMN",
            "SESSION_TOKEN"
        ));
        assert!(has(
            concat!(
                "DefaultEndpointsProtocol=https;AccountName=demo;AccountKey=",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ABCDEFGH;",
                "EndpointSuffix=core.windows.net"
            ),
            "AZURE_STORAGE_ACCOUNT_KEY"
        ));
        assert!(has(
            concat!(
                "client-key-data: ",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ABCDEFGH"
            ),
            "KUBE_CLIENT_KEY_DATA"
        ));
        assert!(has(
            r#"'header' => 'Proxy-Authorization: Basic d3p3bTpqQGNs',"#,
            "BASIC_AUTH"
        ));
        assert!(has(
            "- Bearer 0a000aa0a0a0000000a000a0a0a00000a0a000aaaa0a000aa0aaa000a0a0a000",
            "BEARER_TOKEN"
        ));
        assert!(has(
            "CREATE ROLE app WITH LOGIN PASSWORD 's3cret';",
            "SQL_PASSWORD"
        ));
        assert!(has(
            "CREATE USER root@'host' IDENTIFIED BY \"p4ssw0rd\";",
            "SQL_PASSWORD"
        ));
        assert!(has(
            "ALTER USER root IDENTIFIED WITH mysql_native_password BY hunter2;",
            "SQL_PASSWORD"
        ));
        assert!(has(
            "ALTER LOGIN bob WITH PASSWORD = 'Adm1nPass';",
            "SQL_PASSWORD"
        ));
        assert!(!has(
            "Authorization: Bearer YOUR_ACCESS_TOKEN_VALUE",
            "BEARER_TOKEN"
        ));
        assert!(!has("Bearer abcdefghijklmnopqrstuv", "BEARER_TOKEN"));
        assert!(has(
            r#"if auth != "Basic bnJna2w6dmdycWpz" {"#,
            "BASIC_AUTH"
        ));
        assert!(has(r#"header: "Basic dXNlcjpwYXNz""#, "BASIC_AUTH"));
        assert!(has(
            "jwt=eyJhbGciOiJIUzI1NiJ9.abcdefghijklmnop.abcdefghijklmnop",
            "JWT_SECRET"
        ));
        assert!(!has(
            "jwe=eyJhbGciOiJSU0EtT0FFUCJ9.abcdefghijklmnop.abcdefghijklmnop.abcdefghijklmnop.abcdefghijklmnop",
            "JWT_SECRET"
        ));
        assert!(!has(
            "port=5432 workers=4 timeout_ms=30000 status=200",
            "KEYED_SECRET"
        ));
        assert!(!has("jwt_like=aaa.bbb.ccc css=#aabbcc", "SESSION_TOKEN"));
        assert!(!has("documentation says Basic docs", "BASIC_AUTH"));
        assert!(!has(r#"header: "Basic something""#, "BASIC_AUTH"));
        assert!(!has(r#"header: "Basic dXNlcm9ubHk=""#, "BASIC_AUTH"));
        assert!(!has("password field docs", "SQL_PASSWORD"));
        assert!(!has(
            "CREATE ROLE app WITH LOGIN PASSWORD NULL;",
            "SQL_PASSWORD"
        ));
    }

    #[test]
    fn home_paths_mask_only_local_username_segment() {
        let det = RuleDetector::builtin();
        let cases = [
            (r#"C:\Users\alice\project\main.rs"#, "alice"),
            (r#"C:/Users/alice/project/main.rs"#, "alice"),
            ("/home/bob/project/main.rs", "bob"),
            ("/Users/carol/Library/Logs/app.log", "carol"),
            ("/var/home/frank/.config/app.toml", "frank"),
            ("/export/home/grace/work/app.log", "grace"),
            ("~heidi/src/main.rs", "heidi"),
            ("/mnt/c/Users/dave/code/app.log", "dave"),
            ("/c/Users/erin/code/app.log", "erin"),
        ];
        for (raw, username) in cases {
            let spans = det.detect(&NormalizedView::build(&region(raw), raw));
            let Some(span) = spans.iter().find(|s| s.label == "LOCAL_USERNAME") else {
                panic!("{raw} should detect LOCAL_USERNAME, got {spans:?}");
            };
            assert_eq!(&raw[span.range.start..span.range.end], username);
        }
    }

    #[test]
    fn shared_home_directories_are_not_local_usernames() {
        let det = RuleDetector::builtin();
        for raw in [
            r#"C:\Users\Public\Downloads\file.txt"#,
            "/Users/Shared/cache/file.txt",
            "/home/../project",
        ] {
            let spans = det.detect(&NormalizedView::build(&region(raw), raw));
            assert!(
                spans.iter().all(|s| s.label != "LOCAL_USERNAME"),
                "{raw} should not mask a shared/system directory: {spans:?}"
            );
        }
    }

    #[test]
    fn my_number_does_not_mask_uuid_tail() {
        let det = RuleDetector::builtin();
        let uuidish = "request_id=550e8400-e29b-41d4-a716-000000000019";
        let uuid_spans = det.detect(&NormalizedView::build(&region(uuidish), uuidish));
        assert!(
            uuid_spans.iter().all(|s| s.label != "JP_MY_NUMBER"),
            "uuid tail should not mask as My Number: {uuid_spans:?}"
        );

        let raw = "my_number=123456789018, ok";
        let spans = det.detect(&NormalizedView::build(&region(raw), raw));
        let Some(span) = spans.iter().find(|s| s.label == "JP_MY_NUMBER") else {
            panic!("standalone My Number should still detect: {spans:?}");
        };
        assert_eq!(&raw[span.range.start..span.range.end], "123456789018");
    }

    #[test]
    fn ipv6_does_not_match_rust_namespace_separators() {
        let det = RuleDetector::builtin();
        let rust = r#"std::fs::write(root.join("target"), "SECRET=ignored\n").unwrap();"#;
        let spans = det.detect(&NormalizedView::build(&region(rust), rust));
        assert!(
            spans.iter().all(|s| s.label != "IP_ADDRESS_V6"),
            "Rust namespace separators should not be IPv6: {spans:?}"
        );

        let ipv6 = "bind [::1]:8080 and fe80::1%eth0";
        let spans = det.detect(&NormalizedView::build(&region(ipv6), ipv6));
        assert!(
            spans.iter().any(|s| s.label == "IP_ADDRESS_V6"),
            "real IPv6 should still be detected: {spans:?}"
        );
    }

    #[test]
    fn capture_masks_only_the_selected_group() {
        let det = RuleDetector::from_specs(vec![RuleSpec {
            pattern: r"(?i)api[_-]?key\s*=\s*([A-Za-z0-9]{12})".into(),
            category: Category::Secret,
            label: "API_KEY".into(),
            confidence: Confidence::High,
            validator: Validator::None,
            context: Default::default(),
            capture: 1,
            prefilter: Vec::new(),
        }])
        .unwrap();
        let raw = "api_key = ABCDEFGH1234";
        let spans = det.detect(&NormalizedView::build(&region(raw), raw));
        assert_eq!(spans.len(), 1);
        assert_eq!(
            &raw[spans[0].range.start..spans[0].range.end],
            "ABCDEFGH1234"
        );
    }

    #[test]
    fn missing_capture_is_rejected() {
        assert!(RuleDetector::from_specs(vec![RuleSpec {
            pattern: r"API-[A-Z0-9]+".into(),
            category: Category::Secret,
            label: "API_KEY".into(),
            confidence: Confidence::High,
            validator: Validator::None,
            context: Default::default(),
            capture: 1,
            prefilter: Vec::new(),
        }])
        .is_err());
    }

    #[test]
    fn prefilter_skips_absent_literal_and_keeps_capture() {
        let det = RuleDetector::from_specs(vec![RuleSpec {
            pattern: r"(?i)acme.{0,20}([A-Z0-9]{12})".into(),
            category: Category::Secret,
            label: "ACME_TOKEN".into(),
            confidence: Confidence::High,
            validator: Validator::None,
            context: Default::default(),
            capture: 1,
            prefilter: vec!["acme".into()],
        }])
        .unwrap();
        let miss = "token ABCDEFGH1234";
        assert!(det
            .detect(&NormalizedView::build(&region(miss), miss))
            .is_empty());
        let hit = "acme token ABCDEFGH1234";
        let spans = det.detect(&NormalizedView::build(&region(hit), hit));
        assert_eq!(
            &hit[spans[0].range.start..spans[0].range.end],
            "ABCDEFGH1234"
        );
    }

    #[test]
    fn merged_candidate_scan_preserves_overlapping_rules() {
        let det = RuleDetector::from_specs(vec![
            RuleSpec {
                pattern: r"https://[^\s]+".into(),
                category: Category::Endpoint,
                label: "URL".into(),
                confidence: Confidence::Medium,
                validator: Validator::None,
                context: Default::default(),
                capture: 0,
                prefilter: Vec::new(),
            },
            RuleSpec {
                pattern: r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+".into(),
                category: Category::Secret,
                label: "SLACK_WEBHOOK".into(),
                confidence: Confidence::High,
                validator: Validator::None,
                context: Default::default(),
                capture: 0,
                prefilter: Vec::new(),
            },
        ])
        .unwrap();
        let raw = "https://hooks.slack.com/services/T000/B000/abcd";
        let labels: Vec<_> = det
            .detect(&NormalizedView::build(&region(raw), raw))
            .into_iter()
            .map(|s| s.label)
            .collect();
        assert!(labels.contains(&"URL".to_string()), "{labels:?}");
        assert!(labels.contains(&"SLACK_WEBHOOK".to_string()), "{labels:?}");
    }

    #[test]
    fn prefilter_collects_overlapping_literals() {
        let det = RuleDetector::from_specs(vec![
            RuleSpec {
                pattern: r"abc[a-z0-9]{3}".into(),
                category: Category::Secret,
                label: "SHORT_PREFIX".into(),
                confidence: Confidence::Medium,
                validator: Validator::None,
                context: Default::default(),
                capture: 0,
                prefilter: vec!["abc".into()],
            },
            RuleSpec {
                pattern: r"abcd[0-9]{2}".into(),
                category: Category::Secret,
                label: "LONG_PREFIX".into(),
                confidence: Confidence::High,
                validator: Validator::None,
                context: Default::default(),
                capture: 0,
                prefilter: vec!["abcd".into()],
            },
        ])
        .unwrap();
        let raw = "abcd12";
        let labels: Vec<_> = det
            .detect(&NormalizedView::build(&region(raw), raw))
            .into_iter()
            .map(|s| s.label)
            .collect();
        assert!(labels.contains(&"SHORT_PREFIX".to_string()), "{labels:?}");
        assert!(labels.contains(&"LONG_PREFIX".to_string()), "{labels:?}");
    }
}
