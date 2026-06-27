use crate::session::RecoveryStore;
#[cfg(test)]
use crate::session::Session;
use pentect_core::placeholder::{identity_hash, render_placeholder};
use pentect_core::{
    load_pack, ByteRange, Config, Context, Engine, Input, Kind, MaskResult, Profile, ProfilePolicy,
    Recovery, Region, RegionKind, SensitiveKeyDetector, ShapeGuard, ToolResultParser,
};
use std::collections::HashMap;
use std::sync::OnceLock;

const ENV_ALIAS_LABEL: &str = "PENTECT_ENV_ALIAS";
const ENV_ALIAS_RECORD_PREFIX: &str = "\u{1f}pentect-env\0";
const EXTENSION_PACKS_ENV: &str = "PENTECT_EXTENSION_PACKS";
const BATCH_DELIMITERS: [&str; 4] = [
    "\u{1f}pentect-batch-0\u{1e}",
    "\u{1f}pentect-batch-1\u{1d}",
    "\u{1f}pentect-batch-2\u{1c}",
    "\u{1f}pentect-batch-3\u{1b}",
];

pub(crate) struct ToolScalarInput {
    pub(crate) text: String,
    pub(crate) region_kind: RegionKind,
    pub(crate) key: Option<String>,
    pub(crate) path: Option<String>,
    pub(crate) hints: Vec<String>,
}

pub(crate) struct OutputMasker {
    store: RecoveryStore,
    engine: Engine,
    mode: OutputMaskerMode,
    pending: Recovery,
}

enum OutputMaskerMode {
    Shared,
    Deferred { remask_recoveries: Vec<Recovery> },
}

impl OutputMasker {
    pub(crate) fn new_shared(store: RecoveryStore) -> Result<Self, String> {
        let key = store.session.key;
        Ok(Self {
            store,
            engine: tool_boundary_engine()?,
            mode: OutputMaskerMode::Shared,
            pending: Recovery::empty_for_key(&key),
        })
    }

    pub(crate) fn new_deferred(store: RecoveryStore) -> Result<Self, String> {
        let key = store.session.key;
        let remask_recoveries = store.snapshot()?;
        Ok(Self {
            store,
            engine: tool_boundary_engine()?,
            mode: OutputMaskerMode::Deferred { remask_recoveries },
            pending: Recovery::empty_for_key(&key),
        })
    }

    pub(crate) fn flush(&mut self) -> Result<(), String> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let next = Recovery::empty_for_key(&self.store.session.key);
        let pending = std::mem::replace(&mut self.pending, next);
        self.store.add_recovery(pending)
    }

    pub(crate) fn mask_tool_output(&mut self, text: &str) -> Result<String, String> {
        let kind = if looks_like_sensitive_env_output(text) || looks_like_env_output(text) {
            Kind::Env
        } else {
            Kind::Text
        };
        self.mask_text(text, kind)
    }

    pub(crate) fn mask_text(&mut self, text: &str, kind: Kind) -> Result<String, String> {
        let redacted = redact_env_derivative_lines(text);
        let remasked = self.remask_all(&redacted)?;
        let needs_text_pass = !matches!(kind, Kind::Text | Kind::ToolResult);
        let cfg = Config {
            disclose_length: true,
            ..Config::new(self.store.session.key)
        };
        let result = self.engine.mask(
            Input {
                kind,
                data: remasked,
            },
            &cfg,
        );
        let mut masked = result.masked;
        let mut recovery = result.recovery;
        if needs_text_pass {
            let text_result = self.engine.mask(
                Input {
                    kind: Kind::Text,
                    data: masked,
                },
                &cfg,
            );
            masked = text_result.masked;
            recovery.extend_same_key(text_result.recovery);
        }
        recovery.extend_same_key(env_alias_recovery(&masked, &self.store.session.key));
        self.record_recovery(recovery)?;
        Ok(masked)
    }

    pub(crate) fn mask_tool_result_scalar(
        &mut self,
        text: &str,
        region_kind: RegionKind,
        key: Option<&str>,
        path: Option<&str>,
        hints: &[String],
    ) -> Result<String, String> {
        let redacted = redact_env_derivative_lines(text);
        let remasked = self.remask_all(&redacted)?;
        let cfg = Config {
            disclose_length: true,
            ..Config::new(self.store.session.key)
        };
        let result = self.engine.mask_context(
            remasked,
            Context {
                path: path.map(str::to_string),
                key: key.map(str::to_string),
                hints: hints.to_vec(),
                kind: region_kind,
                format: Kind::ToolResult,
            },
            &cfg,
        );
        self.record_mask_result(result)
    }

    pub(crate) fn mask_tool_result_scalars(
        &mut self,
        scalars: &[ToolScalarInput],
    ) -> Result<Vec<String>, String> {
        if scalars.is_empty() {
            return Ok(Vec::new());
        }
        let mut prepared = Vec::with_capacity(scalars.len());
        for scalar in scalars {
            let redacted = redact_env_derivative_lines(&scalar.text);
            prepared.push(self.remask_all(&redacted)?);
        }
        let Some(delimiter) = choose_batch_delimiter(&prepared) else {
            return scalars
                .iter()
                .map(|scalar| {
                    self.mask_tool_result_scalar(
                        &scalar.text,
                        scalar.region_kind,
                        scalar.key.as_deref(),
                        scalar.path.as_deref(),
                        &scalar.hints,
                    )
                })
                .collect();
        };

        let mut raw = String::new();
        let mut regions = Vec::with_capacity(scalars.len());
        for (index, (scalar, text)) in scalars.iter().zip(prepared.iter()).enumerate() {
            if index > 0 {
                raw.push_str(delimiter);
            }
            let start = raw.len();
            raw.push_str(text);
            let end = raw.len();
            regions.push(Region {
                span: ByteRange::new(start, end),
                ctx: Context {
                    path: scalar.path.clone(),
                    key: scalar.key.clone(),
                    hints: scalar.hints.clone(),
                    kind: scalar.region_kind,
                    format: Kind::ToolResult,
                },
            });
        }

        let cfg = Config {
            disclose_length: true,
            ..Config::new(self.store.session.key)
        };
        let result = self.engine.mask_regions(raw, regions, &cfg);
        let masked = self.record_mask_result(result)?;
        let parts: Vec<String> = masked.split(delimiter).map(str::to_string).collect();
        if parts.len() != scalars.len() {
            return Err("internal error: batched tool-result masking split mismatch".to_string());
        }
        Ok(parts)
    }

    fn record_mask_result(&mut self, result: MaskResult) -> Result<String, String> {
        let masked = result.masked;
        let mut recovery = result.recovery;
        recovery.extend_same_key(env_alias_recovery(&masked, &self.store.session.key));
        self.record_recovery(recovery)?;
        Ok(masked)
    }

    fn record_recovery(&mut self, recovery: Recovery) -> Result<(), String> {
        if recovery.is_empty() {
            return Ok(());
        }
        match &mut self.mode {
            OutputMaskerMode::Shared => self.store.add_recovery(recovery)?,
            OutputMaskerMode::Deferred { .. } => self.pending.extend_same_key(recovery),
        }
        Ok(())
    }

    fn remask_all(&self, text: &str) -> Result<String, String> {
        match &self.mode {
            OutputMaskerMode::Shared => self.store.remask_all(text),
            OutputMaskerMode::Deferred { remask_recoveries } => {
                let mut out = text.to_string();
                for rec in remask_recoveries {
                    out = rec.remask(&out);
                }
                Ok(out)
            }
        }
    }
}

fn choose_batch_delimiter(values: &[String]) -> Option<&'static str> {
    BATCH_DELIMITERS
        .iter()
        .copied()
        .find(|delimiter| values.iter().all(|value| !value.contains(delimiter)))
}

fn tool_boundary_engine() -> Result<Engine, String> {
    let mut builder = Engine::builder()
        .standard_stack(Profile::Strict.knobs())
        .parser(Kind::ToolResult, Box::new(ToolResultParser))
        .detector(Box::new(SensitiveKeyDetector));
    for pack in extension_packs_from_env()? {
        builder = builder.detector(Box::new(pack.rules));
    }
    Ok(builder
        .policy(Box::new(ProfilePolicy::new(Profile::Strict)))
        .guard(Box::new(ShapeGuard::builtin()))
        .build())
}

fn extension_packs_from_env() -> Result<Vec<pentect_core::Pack>, String> {
    static CACHE: OnceLock<Result<Vec<pentect_core::Pack>, String>> = OnceLock::new();
    CACHE.get_or_init(load_extension_packs_from_env).clone()
}

fn load_extension_packs_from_env() -> Result<Vec<pentect_core::Pack>, String> {
    let Some(value) = std::env::var_os(EXTENSION_PACKS_ENV) else {
        return Ok(Vec::new());
    };
    let mut packs = Vec::new();
    for path in std::env::split_paths(&value) {
        if path.as_os_str().is_empty() {
            continue;
        }
        if !path.is_file() {
            return Err(format!("extension pack does not exist: {}", path.display()));
        }
        let src = std::fs::read_to_string(&path)
            .map_err(|e| format!("could not read extension pack '{}': {e}", path.display()))?;
        packs.push(
            load_pack(&src)
                .map_err(|e| format!("extension pack '{}' is invalid: {e}", path.display()))?,
        );
    }
    Ok(packs)
}

#[cfg(test)]
pub(crate) fn mask_tool_output(session: &Session, text: &str) -> Result<String, String> {
    let store = RecoveryStore::load(session)?;
    OutputMasker::new_shared(store)?.mask_tool_output(text)
}

#[cfg(test)]
pub(crate) fn mask_live_output(session: &Session, text: &str) -> Result<String, String> {
    let store = RecoveryStore::load(session)?;
    OutputMasker::new_shared(store)?.mask_text(text, live_output_kind(text))
}

pub(crate) fn live_output_kind(text: &str) -> Kind {
    if looks_like_sensitive_env_output(text)
        || looks_like_env_output(text)
        || text.lines().any(|line| is_env_assignment_line(line.trim()))
    {
        Kind::Env
    } else {
        Kind::Text
    }
}

fn looks_like_env_output(text: &str) -> bool {
    let mut env_lines = 0usize;
    let mut non_empty_lines = 0usize;
    let mut strong_key = false;
    for line in text.lines().take(256) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        non_empty_lines += 1;
        if let Some(key) = env_assignment_key(trimmed) {
            env_lines += 1;
            strong_key |= is_strong_env_output_key(key);
        }
    }
    env_lines >= 2 && env_lines == non_empty_lines && strong_key
}

fn looks_like_sensitive_env_output(text: &str) -> bool {
    for line in text.lines().take(256) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(key) = env_assignment_key(trimmed) {
            if is_sensitive_env_output_name(&key.to_ascii_lowercase()) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
pub(crate) fn first_reusable_env_name(masked: &str) -> Option<String> {
    reusable_env_aliases(masked)
        .into_iter()
        .next()
        .map(|(name, _)| name)
}

fn env_alias_recovery(masked: &str, key: &[u8; 32]) -> Recovery {
    let aliases = reusable_env_aliases(masked);
    if aliases.is_empty() {
        return Recovery::empty_for_key(key);
    }
    let map = aliases
        .into_iter()
        .map(|(name, handle)| {
            (
                env_alias_placeholder(key, &name, &handle),
                encode_env_alias_record(&name, &handle),
            )
        })
        .collect::<HashMap<_, _>>();
    Recovery::seal(map, key)
}

fn reusable_env_aliases(text: &str) -> Vec<(String, String)> {
    let mut out = reusable_assignment_env_aliases(text);
    out.extend(reusable_handle_env_aliases(text));
    out
}

fn reusable_assignment_env_aliases(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let Some((key, value)) = trimmed
            .strip_prefix("export ")
            .unwrap_or(trimmed)
            .split_once('=')
        else {
            continue;
        };
        if !is_env_name(key) {
            continue;
        }
        let handle = value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .trim_end_matches(';');
        if is_reusable_placeholder(handle) {
            out.push((key.to_string(), handle.to_string()));
        }
    }
    out
}

fn reusable_handle_env_aliases(text: &str) -> Vec<(String, String)> {
    reusable_placeholders(text)
        .into_iter()
        .filter_map(|handle| {
            let name = env_name_for_handle(&handle)?;
            Some((name, handle))
        })
        .collect()
}

fn reusable_placeholders(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        if bytes[i] == b'<' && bytes[i + 1] == b'<' {
            if let Some(close) = find_from(bytes, i + 2, b">>") {
                let handle = &text[i..close + 2];
                if is_reusable_placeholder(handle) {
                    out.push(handle.to_string());
                }
                i = close + 2;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn env_name_for_handle(handle: &str) -> Option<String> {
    let core = placeholder_core(handle)?;
    Some(format!("PENTECT_{core}"))
}

fn env_alias_placeholder(key: &[u8; 32], name: &str, handle: &str) -> String {
    let hash = identity_hash(key, &format!("env-alias:{name}:{handle}"));
    render_placeholder(ENV_ALIAS_LABEL, &hash, None)
}

pub(crate) fn is_env_alias_placeholder(value: &str) -> bool {
    placeholder_label(value) == Some(ENV_ALIAS_LABEL)
}

fn encode_env_alias_record(name: &str, handle: &str) -> String {
    format!("{ENV_ALIAS_RECORD_PREFIX}{name}\0{handle}")
}

pub(crate) fn decode_env_alias_record(record: &str) -> Option<(&str, &str)> {
    let rest = record.strip_prefix(ENV_ALIAS_RECORD_PREFIX)?;
    let (name, handle) = rest.split_once('\0')?;
    if is_env_name(name) && is_reusable_placeholder(handle) {
        Some((name, handle))
    } else {
        None
    }
}

pub(crate) fn contains_unresolved_masked_handle(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        if bytes[i] == b'<' && bytes[i + 1] == b'<' {
            if let Some(close) = find_from(bytes, i + 2, b">>") {
                if is_reusable_placeholder(&text[i..close + 2]) {
                    return true;
                }
                i = close + 2;
                continue;
            }
        }
        i += 1;
    }
    false
}

fn find_from(hay: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || start >= hay.len() {
        return None;
    }
    let mut i = start;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn is_reusable_placeholder(value: &str) -> bool {
    value.starts_with("<<")
        && value.ends_with(">>")
        && value.contains('_')
        && !value.contains("REDACTED_DERIVED")
        && placeholder_label(value) != Some(ENV_ALIAS_LABEL)
}

fn placeholder_core(value: &str) -> Option<&str> {
    let inner = value.strip_prefix("<<")?.strip_suffix(">>")?;
    let inner = match inner.rsplit_once("_length_at_least_") {
        Some((prefix, suffix))
            if suffix
                .strip_suffix("_chars")
                .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit())) =>
        {
            prefix
        }
        _ => inner,
    };
    let inner = match inner.rsplit_once("_len") {
        Some((prefix, suffix)) if suffix.bytes().all(|b| b.is_ascii_digit()) => prefix,
        _ => inner,
    };
    if inner
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        Some(inner)
    } else {
        None
    }
}

fn placeholder_label(value: &str) -> Option<&str> {
    let inner = placeholder_core(value)?;
    let (label, hash) = inner.rsplit_once('_')?;
    if hash.len() == 16 && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(label)
    } else {
        None
    }
}

fn is_env_name(name: &str) -> bool {
    !name.is_empty() && !name.as_bytes()[0].is_ascii_digit() && name.bytes().all(is_env_name_byte)
}

fn redact_env_derivative_lines(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut changed = false;
    for segment in text.split_inclusive('\n') {
        let (body, ending) = split_line_ending(segment);
        if let Some(key) =
            env_derivative_assignment_key(body).or_else(|| env_derivative_summary_key(body))
        {
            let indent_len = body.len() - body.trim_start().len();
            out.push_str(&body[..indent_len]);
            out.push_str(key);
            out.push_str("=<<REDACTED_DERIVED>>");
            out.push_str(ending);
            changed = true;
        } else {
            out.push_str(segment);
        }
    }
    if changed {
        out
    } else {
        text.to_string()
    }
}

fn split_line_ending(line: &str) -> (&str, &'static str) {
    let mut body = line;
    let mut ending = "";
    if let Some(stripped) = body.strip_suffix('\n') {
        body = stripped;
        ending = "\n";
    }
    if let Some(stripped) = body.strip_suffix('\r') {
        body = stripped;
        ending = if ending.is_empty() { "\r" } else { "\r\n" };
    }
    (body, ending)
}

fn env_derivative_assignment_key(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let (key, value) = trimmed.split_once('=')?;
    if key.is_empty() || value.is_empty() || !key.chars().all(is_env_summary_key_char) {
        return None;
    }
    is_derived_output_key(key).then_some(key)
}

fn env_derivative_summary_key(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let key_end = trimmed
        .char_indices()
        .find(|(_, ch)| !is_env_summary_key_char(*ch))
        .map(|(i, _)| i)
        .unwrap_or(trimmed.len());
    if key_end == 0 || key_end == trimmed.len() {
        return None;
    }
    let key = &trimmed[..key_end];
    if !looks_like_env_summary_key(key) {
        return None;
    }
    let rest = &trimmed[key_end..];
    if rest.starts_with('=') {
        return None;
    }
    (contains_secret_derivative_marker(rest) || looks_like_tabular_derivative(rest)).then_some(key)
}

fn is_env_summary_key_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-')
}

fn looks_like_env_summary_key(key: &str) -> bool {
    if key.is_empty() || key.as_bytes()[0].is_ascii_digit() {
        return false;
    }
    let lower = key.to_ascii_lowercase();
    is_sensitive_env_output_name(&lower)
        || key.contains('_')
        || key.contains('.')
        || key.contains('-')
        || key.chars().any(|ch| ch.is_ascii_uppercase())
}

fn is_sensitive_env_output_name(name: &str) -> bool {
    name == "key" || is_sensitive_env_name(name)
}

fn is_derived_output_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    [
        "prefix", "suffix", "length", "len", "base64", "b64", "hex", "encoded", "hash", "digest",
        "sha1", "sha256",
    ]
    .iter()
    .any(|marker| lower == *marker || lower.contains(&format!("{marker}_")))
}

fn contains_secret_derivative_marker(rest: &str) -> bool {
    let lower = rest.to_ascii_lowercase();
    [
        "masked",
        "preview",
        "prefix",
        "suffix",
        "first",
        "last",
        "length",
        "len=",
        "hex",
        "base64",
        "b64",
        "encoded",
        "hash",
        "digest",
        "sha1",
        "sha256",
        "starts_with",
        "ends_with",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn looks_like_tabular_derivative(rest: &str) -> bool {
    let mut words = rest.split_whitespace();
    let Some(first) = words.next() else {
        return false;
    };
    if first.chars().all(|ch| ch.is_ascii_digit()) {
        return true;
    }
    matches!(first.to_ascii_lowercase().as_str(), "length" | "len")
        && words.any(|word| word.chars().all(|ch| ch.is_ascii_digit()))
}

fn is_strong_env_output_key(key: &str) -> bool {
    is_sensitive_env_output_name(&key.to_ascii_lowercase())
        || key.chars().any(|ch| ch.is_ascii_uppercase())
}

fn is_env_assignment_line(line: &str) -> bool {
    env_assignment_key(line).is_some()
}

fn env_assignment_key(line: &str) -> Option<&str> {
    let line = line.strip_prefix("export ").unwrap_or(line);
    let (key, value) = line.split_once('=')?;
    if key.is_empty() || value.is_empty() {
        return None;
    }
    if key
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
    {
        Some(key)
    } else {
        None
    }
}

pub(crate) fn is_env_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

pub(crate) fn is_sensitive_env_name(name: &str) -> bool {
    if name == "auth"
        || name == "authorization"
        || name.contains("auth_")
        || name.contains("_auth")
        || name.contains("authorization")
    {
        return true;
    }
    [
        "api_key",
        "apikey",
        "access_key",
        "secret",
        "token",
        "password",
        "passwd",
        "passcode",
        "private",
        "credential",
        "otp",
        "totp",
        "mfa",
        "session",
        "cookie",
        "jwt",
        "bearer",
    ]
    .iter()
    .any(|needle| name.contains(needle))
}

pub(crate) fn is_ascii_word_char(ch: Option<char>) -> bool {
    ch.is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
}
