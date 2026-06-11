use super::validate::Validator;
use super::Detector;
use crate::model::*;
use crate::normalize::NormalizedView;
use regex::{Regex, RegexSet};

struct Rule {
    re: Regex,
    category: Category,
    label: String,
    confidence: Confidence,
    /// Checksum gate applied to each match before it becomes a span (the
    /// precision lever that lets a permissive pattern avoid false positives).
    validator: Validator,
}

/// A data-form rule (e.g. a TOML pack entry) before its pattern is compiled.
pub struct RuleSpec {
    pub pattern: String,
    pub category: Category,
    pub label: String,
    pub confidence: Confidence,
    pub validator: Validator,
}

/// Anchored vendor-token rules. High confidence and linear-time (no ReDoS), so
/// these bypass the entropy/profile uncertainty. The built-in set is just the
/// default pack — `from_specs` builds the same detector from loaded data.
pub struct RuleDetector {
    rules: Vec<Rule>,
    /// All patterns in one DFA: one pass says which rules match anywhere, so we
    /// only run per-rule `find_iter` for those (cheap on secret-free regions).
    set: RegexSet,
}

impl RuleDetector {
    /// Compile data-form rules into a detector; errors if any pattern is invalid.
    pub fn from_specs(specs: Vec<RuleSpec>) -> Result<Self, String> {
        let set = RegexSet::new(specs.iter().map(|s| s.pattern.as_str()))
            .map_err(|e| format!("rule set: {e}"))?;
        let rules = specs
            .into_iter()
            .map(|s| {
                Ok(Rule {
                    re: Regex::new(&s.pattern).map_err(|e| format!("rule {}: {e}", s.label))?,
                    category: s.category,
                    label: s.label,
                    confidence: s.confidence,
                    validator: s.validator,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self { rules, set })
    }

    pub fn builtin() -> Self {
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
            (
                r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*",
                Secret,
                "JWT_SECRET",
                High,
            ),
            (r"AKIA[A-Z0-9]{16}", Secret, "AWS_AKID", High),
            (r"sk-[A-Za-z0-9_-]{20,}", Secret, "OPENAI_API_KEY", High),
            (r"xox[baprs]-[A-Za-z0-9-]{10,}", Secret, "SLACK_TOKEN", High),
            (
                r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
                Secret,
                "SLACK_WEBHOOK",
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
            (r"SK[0-9a-fA-F]{32}", Secret, "TWILIO_API_KEY", Medium),
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
                r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?)://[^\s:/@]+:[^\s:/@]+@[^\s/?#]+",
                Secret,
                "DB_CONNECTION_STRING",
                High,
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
            // No checksum, so context-gated: a bare letter+8-digits is any SKU.
            (
                r"(?i)passport[^\n]{0,12}?\b[A-Z][0-9]{8}\b",
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
                r#"(?i)\b(?:https?|ftp|ftps|wss?)://[^\s"'<>()]+"#,
                Endpoint,
                "URL",
                Medium,
            ),
            // Context-gated like Presidio: a bare number/ID only fires next to its
            // keyword, so these don't flood. The match includes the keyword.
            (
                r"(?i)\bacc(?:ount|t)\b[^\n]{0,15}?\b[0-9]{8,17}\b",
                Identifier,
                "US_BANK_ACCOUNT",
                Low,
            ),
            (
                r"(?i)(?:driver'?s?\s*licen[sc]e|\bDLN?\b)[^\n]{0,15}?\b[A-Z0-9]{5,13}\b",
                Identifier,
                "US_DRIVER_LICENSE",
                Low,
            ),
        ];
        use Validator as V;
        // Checksum-gated detectors: a permissive pattern finds candidates, the
        // validator (Luhn, mod-97, Verhoeff, weighted mod-N, ...) confirms them.
        // This is how we match/exceed Presidio's recognizers deterministically.
        #[rustfmt::skip]
        let checked: &[(&str, Category, &str, Confidence, Validator)] = &[
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
            (r"\b[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}\b", Pii, "JP_MY_NUMBER", High, V::JpMyNumber),
            (r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b", Pii, "BR_CPF", High, V::BrCpf),
            (r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b", Identifier, "BR_CNPJ", High, V::BrCnpj),
            (r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", Identifier, "BTC_ADDRESS", High, V::BtcAddress),
            (r"\b[LM3][a-km-zA-HJ-NP-Z1-9]{25,34}\b", Identifier, "LTC_ADDRESS", High, V::LtcAddress),
            (r"\br[rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz]{24,34}\b", Identifier, "XRP_ADDRESS", High, V::XrpAddress),
            (r"\b[5KL][a-km-zA-HJ-NP-Z1-9]{50,51}\b", Secret, "CRYPTO_PRIVATE_KEY_WIF", High, V::Wif),
            (r"\b[0-8][0-9]{2}[- ][0-9]{2}[- ][0-9]{4}\b", Pii, "US_SSN", Medium, V::UsSsn),
            (r"\bbc1[02-9ac-hj-np-z]{6,87}\b", Identifier, "BTC_ADDRESS_BECH32", High, V::BtcBech32),
            (r"\b0x[0-9a-fA-F]{40}\b", Identifier, "ETH_ADDRESS", High, V::EthAddress),
            (r"\b(?:[a-z]{3,8} ){11,23}[a-z]{3,8}\b", Secret, "BIP39_MNEMONIC", High, V::Bip39),
            (r"(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4}(?:%[0-9A-Za-z]+)?(?:/(?:12[0-8]|1[01][0-9]|[1-9]?[0-9]))?", Endpoint, "IP_ADDRESS_V6", High, V::Ipv6),
            (r"\b[0-9]{6}[-+A-Y][0-9]{3}[0-9A-Y]\b", Identifier, "FI_HETU", High, V::FiHetu),
            (r"(?i)\b[A-Z]{6}[0-9A-Z]{2}[A-Z][0-9A-Z]{2}[A-Z][0-9A-Z]{3}[A-Z]\b", Identifier, "IT_FISCAL_CODE", High, V::ItFiscalCode),
            (r"\b[12][0-9]{4}(?:[0-9]{2}|2[AB])[0-9]{8}\b", Identifier, "FR_NIR_INSEE", High, V::FrNir),
        ];
        let specs = table
            .iter()
            .map(|&(pattern, category, label, confidence)| RuleSpec {
                pattern: pattern.to_string(),
                category,
                label: label.to_string(),
                confidence,
                validator: V::None,
            })
            .chain(
                checked.iter().map(
                    |&(pattern, category, label, confidence, validator)| RuleSpec {
                        pattern: pattern.to_string(),
                        category,
                        label: label.to_string(),
                        confidence,
                        validator,
                    },
                ),
            )
            .collect();
        Self::from_specs(specs).expect("builtin regexes compile")
    }
}

impl Detector for RuleDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let s = view.text();
        let mut out = Vec::new();
        for i in self.set.matches(s) {
            let rule = &self.rules[i];
            for m in rule.re.find_iter(s) {
                if !rule.validator.accepts(m.as_str()) {
                    continue;
                }
                out.push(Span {
                    range: view.to_raw(ByteRange::new(m.start(), m.end())),
                    category: rule.category,
                    label: rule.label.clone(),
                    confidence: rule.confidence,
                    source: DetectorId::Rule,
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::region;

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
        for rule in &RuleDetector::builtin().rules {
            assert!(label_re.is_match(&rule.label), "bad label: {}", rule.label);
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
}
