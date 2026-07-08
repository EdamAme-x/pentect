use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::{Mutex, OnceLock};
use tokenizers::{Tokenizer, TruncationDirection, TruncationParams, TruncationStrategy};
use tract_onnx::prelude::*;

const MODEL_ONNX: &[u8] = include_bytes!("../assets/ner/bert-small-ner-pii-mobile.onnx");
const TOKENIZER_JSON: &[u8] =
    include_bytes!("../assets/ner/bert-small-ner-pii-mobile-tokenizer.json");
const CONFIG_JSON: &str = include_str!("../assets/ner/bert-small-ner-pii-mobile-config.json");

const MAX_TOKENS: usize = 256;
const MAX_CHUNK_BYTES: usize = 2_048;
const MIN_CONFIDENCE: f32 = 0.70;
const MAX_SEGMENTS: usize = 256;

#[derive(Clone, Debug, PartialEq)]
pub struct NerSpan {
    pub start: usize,
    pub end: usize,
    pub label: String,
    pub confidence: &'static str,
}

pub fn detect_pii(text: &str) -> Result<Vec<NerSpan>, String> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let state = ENGINE.get_or_init(|| NerEngine::load().map(Mutex::new));
    let engine = match state {
        Ok(engine) => engine,
        Err(e) => return Err(e.clone()),
    };
    let mut engine = engine
        .lock()
        .map_err(|_| "pii-ner model lock poisoned".to_string())?;
    engine.detect(text)
}

static ENGINE: OnceLock<Result<Mutex<NerEngine>, String>> = OnceLock::new();

struct NerEngine {
    tokenizer: Tokenizer,
    labels: Vec<String>,
    plan: Arc<TypedRunnableModel>,
}

impl NerEngine {
    fn load() -> Result<Self, String> {
        let mut tokenizer =
            Tokenizer::from_bytes(TOKENIZER_JSON).map_err(|e| format!("pii-ner tokenizer: {e}"))?;
        tokenizer
            .with_truncation(Some(TruncationParams {
                max_length: MAX_TOKENS,
                strategy: TruncationStrategy::LongestFirst,
                stride: 0,
                direction: TruncationDirection::Right,
            }))
            .map_err(|e| format!("pii-ner tokenizer truncation: {e}"))?;
        let labels = load_labels()?;
        let mut cursor = Cursor::new(MODEL_ONNX);
        let plan = tract_onnx::onnx()
            .model_for_read(&mut cursor)
            .map_err(|e| format!("pii-ner onnx read: {e}"))?
            .into_optimized()
            .map_err(|e| format!("pii-ner onnx optimize: {e}"))?
            .into_runnable()
            .map_err(|e| format!("pii-ner onnx runnable: {e}"))?;
        Ok(Self {
            tokenizer,
            labels,
            plan,
        })
    }

    fn detect(&mut self, text: &str) -> Result<Vec<NerSpan>, String> {
        let mut spans = Vec::new();
        for (base, chunk) in text_segments(text).take(MAX_SEGMENTS) {
            spans.extend(self.detect_chunk(base, chunk)?);
        }
        Ok(merge_adjacent_spans(spans))
    }

    fn detect_chunk(&mut self, base: usize, chunk: &str) -> Result<Vec<NerSpan>, String> {
        if !has_ner_signal(chunk) {
            return Ok(Vec::new());
        }
        let encoding = self
            .tokenizer
            .encode(chunk, true)
            .map_err(|e| format!("pii-ner tokenize: {e}"))?;
        let ids = encoding
            .get_ids()
            .iter()
            .map(|&id| i64::from(id))
            .collect::<Vec<_>>();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let seq_len = ids.len();
        let attention = encoding
            .get_attention_mask()
            .iter()
            .map(|&value| i64::from(value))
            .collect::<Vec<_>>();
        let token_types = encoding
            .get_type_ids()
            .iter()
            .map(|&value| i64::from(value))
            .collect::<Vec<_>>();

        let input_ids = Tensor::from_shape(&[1, seq_len], &ids)
            .map_err(|e| format!("pii-ner input_ids: {e}"))?
            .into_tvalue();
        let attention_mask = Tensor::from_shape(&[1, seq_len], &attention)
            .map_err(|e| format!("pii-ner attention_mask: {e}"))?
            .into_tvalue();
        let token_type_ids = Tensor::from_shape(&[1, seq_len], &token_types)
            .map_err(|e| format!("pii-ner token_type_ids: {e}"))?
            .into_tvalue();
        let mut outputs = self
            .plan
            .run(tvec!(input_ids, attention_mask, token_type_ids))
            .map_err(|e| format!("pii-ner inference: {e}"))?;
        let output = outputs
            .pop()
            .ok_or_else(|| "pii-ner inference returned no output".to_string())?
            .into_tensor();
        let logits = output
            .to_plain_array_view::<f32>()
            .map_err(|e| format!("pii-ner logits: {e}"))?;
        let shape = logits.shape();
        if shape.len() != 3 || shape[0] != 1 || shape[1] != seq_len || shape[2] != self.labels.len()
        {
            return Err(format!("pii-ner logits shape mismatch: {shape:?}"));
        }
        let raw_logits = logits
            .as_slice_memory_order()
            .ok_or_else(|| "pii-ner logits are not contiguous".to_string())?;
        let spans = spans_from_logits(
            base,
            chunk,
            encoding.get_offsets(),
            raw_logits,
            seq_len,
            &self.labels,
        )
        .into_iter()
        .map(|span| expand_value_span(base, chunk, span))
        .collect();
        Ok(spans)
    }
}

#[derive(Deserialize)]
struct ModelConfig {
    id2label: BTreeMap<String, String>,
}

fn load_labels() -> Result<Vec<String>, String> {
    let config: ModelConfig =
        serde_json::from_str(CONFIG_JSON).map_err(|e| format!("pii-ner config: {e}"))?;
    let mut indexed = Vec::new();
    for (key, label) in config.id2label {
        let idx = key
            .parse::<usize>()
            .map_err(|e| format!("pii-ner label index '{key}': {e}"))?;
        indexed.push((idx, label));
    }
    indexed.sort_by_key(|(idx, _)| *idx);
    if indexed.is_empty() || indexed.iter().enumerate().any(|(i, (idx, _))| i != *idx) {
        return Err("pii-ner labels must be contiguous from zero".to_string());
    }
    Ok(indexed.into_iter().map(|(_, label)| label).collect())
}

fn spans_from_logits(
    base: usize,
    chunk: &str,
    offsets: &[(usize, usize)],
    logits: &[f32],
    seq_len: usize,
    labels: &[String],
) -> Vec<NerSpan> {
    let mut spans = Vec::new();
    let label_count = labels.len();
    let mut open: Option<OpenSpan> = None;
    for token_idx in 0..seq_len {
        let Some(&(start, end)) = offsets.get(token_idx) else {
            flush_open(&mut spans, &mut open);
            continue;
        };
        if start >= end
            || end > chunk.len()
            || !chunk.is_char_boundary(start)
            || !chunk.is_char_boundary(end)
        {
            flush_open(&mut spans, &mut open);
            continue;
        }
        let row = &logits[token_idx * label_count..(token_idx + 1) * label_count];
        let (label_idx, confidence) = best_label(row);
        let label = labels
            .get(label_idx)
            .map(|label| normalize_model_label(label))
            .unwrap_or("O");
        if label == "O" || confidence < MIN_CONFIDENCE {
            flush_open(&mut spans, &mut open);
            continue;
        }
        let mapped = span_label(label);
        let abs_start = base + start;
        let abs_end = base + end;
        match open.as_mut() {
            Some(current)
                if current.label == mapped
                    && abs_start <= current.end.saturating_add(1)
                    && can_merge_token(chunk, start) =>
            {
                current.end = abs_end;
                current.max_confidence = current.max_confidence.max(confidence);
            }
            _ => {
                flush_open(&mut spans, &mut open);
                open = Some(OpenSpan {
                    start: abs_start,
                    end: abs_end,
                    label: mapped.to_string(),
                    max_confidence: confidence,
                });
            }
        }
    }
    flush_open(&mut spans, &mut open);
    spans
}

struct OpenSpan {
    start: usize,
    end: usize,
    label: String,
    max_confidence: f32,
}

fn flush_open(spans: &mut Vec<NerSpan>, open: &mut Option<OpenSpan>) {
    let Some(span) = open.take() else {
        return;
    };
    if span.end <= span.start {
        return;
    }
    spans.push(NerSpan {
        start: span.start,
        end: span.end,
        label: span.label,
        confidence: confidence_bucket(span.max_confidence),
    });
}

fn best_label(logits: &[f32]) -> (usize, f32) {
    let mut best_idx = 0usize;
    let mut best = f32::NEG_INFINITY;
    let mut second = f32::NEG_INFINITY;
    for (idx, &value) in logits.iter().enumerate() {
        if value > best {
            second = best;
            best = value;
            best_idx = idx;
        } else if value > second {
            second = value;
        }
    }
    (best_idx, sigmoid(best - second))
}

fn sigmoid(value: f32) -> f32 {
    1.0 / (1.0 + (-value).exp())
}

fn confidence_bucket(value: f32) -> &'static str {
    if value >= 0.88 {
        "high"
    } else {
        "medium"
    }
}

fn normalize_model_label(label: &str) -> &str {
    if label.starts_with("B-") || label.starts_with("I-") {
        &label[2..]
    } else {
        label
    }
}

fn span_label(label: &str) -> &str {
    match label {
        "GIVENNAME" | "SURNAME" => "PERSON_NAME",
        "BUILDINGNUM" | "STREET" | "CITY" | "ZIPCODE" => "ADDRESS",
        "DATEOFBIRTH" => "DATE_OF_BIRTH",
        "CREDITCARDNUMBER" => "CREDIT_CARD_NUMBER",
        "DRIVERLICENSENUM" => "DRIVER_LICENSE_NUMBER",
        "IDCARDNUM" => "ID_CARD_NUMBER",
        "SOCIALNUM" => "SOCIAL_NUMBER",
        "TELEPHONENUM" => "PHONE_NUMBER",
        "ACCOUNTNUM" => "ACCOUNT_NUMBER",
        "TAXNUM" => "TAX_NUMBER",
        other => other,
    }
}

fn can_merge_token(chunk: &str, token_start: usize) -> bool {
    chunk[..token_start]
        .chars()
        .next_back()
        .is_some_and(|ch| ch.is_whitespace() || matches!(ch, '-' | '_' | '.' | '@' | '/' | '#'))
}

fn merge_adjacent_spans(mut spans: Vec<NerSpan>) -> Vec<NerSpan> {
    spans.sort_by_key(|span| (span.start, span.end));
    let mut merged: Vec<NerSpan> = Vec::new();
    for span in spans {
        if let Some(last) = merged.last_mut() {
            if last.label == span.label && span.start <= last.end.saturating_add(1) {
                last.end = last.end.max(span.end);
                if last.confidence != "high" {
                    last.confidence = span.confidence;
                }
                continue;
            }
        }
        merged.push(span);
    }
    merged
}

fn expand_value_span(base: usize, chunk: &str, mut span: NerSpan) -> NerSpan {
    if !should_expand_label(&span.label) || span.start < base || span.end < span.start {
        return span;
    }
    let mut start = span.start - base;
    let mut end = span.end - base;
    if end > chunk.len() {
        return span;
    }
    while start > 0 {
        let Some((prev_start, ch)) = chunk[..start].char_indices().next_back() else {
            break;
        };
        if !is_value_char(ch) {
            break;
        }
        start = prev_start;
    }
    while end < chunk.len() {
        let Some(ch) = chunk[end..].chars().next() else {
            break;
        };
        if !is_value_char(ch) {
            break;
        }
        end += ch.len_utf8();
    }
    if start < end && chunk.is_char_boundary(start) && chunk.is_char_boundary(end) {
        span.start = base + start;
        span.end = base + end;
    }
    span
}

fn should_expand_label(label: &str) -> bool {
    matches!(
        label,
        "EMAIL"
            | "PASSWORD"
            | "USERNAME"
            | "ACCOUNT_NUMBER"
            | "CREDIT_CARD_NUMBER"
            | "DRIVER_LICENSE_NUMBER"
            | "ID_CARD_NUMBER"
            | "SOCIAL_NUMBER"
            | "TAX_NUMBER"
            | "PHONE_NUMBER"
            | "ZIPCODE"
    )
}

fn is_value_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '+' | '@' | '%' | '/' | '#')
}

fn has_ner_signal(chunk: &str) -> bool {
    chunk
        .bytes()
        .any(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'@' | b'.' | b'-' | b'_'))
}

fn text_segments(text: &str) -> impl Iterator<Item = (usize, &str)> {
    SegmentIter { text, offset: 0 }
}

struct SegmentIter<'a> {
    text: &'a str,
    offset: usize,
}

impl<'a> Iterator for SegmentIter<'a> {
    type Item = (usize, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        while self.offset < self.text.len() {
            let start = self.offset;
            let remaining = &self.text[start..];
            let line_end = remaining
                .find('\n')
                .map(|idx| start + idx + 1)
                .unwrap_or(self.text.len());
            let mut end = line_end.min(start.saturating_add(MAX_CHUNK_BYTES));
            while end > start && !self.text.is_char_boundary(end) {
                end -= 1;
            }
            if end == start {
                self.offset = line_end;
                continue;
            }
            self.offset = if end < line_end { end } else { line_end };
            let raw = self.text[start..end].trim_matches(['\r', '\n']);
            let leading = raw.len() - raw.trim_start().len();
            let chunk = raw.trim_start();
            if chunk.is_empty() {
                continue;
            }
            return Some((start + leading, chunk));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_model_person_parts() {
        let labels = vec![
            "O".to_string(),
            "GIVENNAME".to_string(),
            "SURNAME".to_string(),
        ];
        let mut logits = vec![0.0f32; 4 * labels.len()];
        logits[labels.len() + 1] = 8.0;
        logits[labels.len() * 2 + 2] = 8.0;
        let spans = spans_from_logits(
            0,
            "Ada Lovelace",
            &[(0, 0), (0, 3), (4, 12), (0, 0)],
            &logits,
            4,
            &labels,
        );
        assert_eq!(
            spans,
            vec![NerSpan {
                start: 0,
                end: 12,
                label: "PERSON_NAME".to_string(),
                confidence: "high",
            }]
        );
    }

    #[test]
    fn segments_keep_offsets() {
        let items = text_segments("a\n  John Smith\n").collect::<Vec<_>>();
        assert_eq!(items[0], (0, "a"));
        assert_eq!(items[1], (4, "John Smith"));
    }

    #[test]
    fn expands_partial_secret_like_model_span() {
        let raw = "password: hunter2";
        let span = expand_value_span(
            0,
            raw,
            NerSpan {
                start: 10,
                end: 16,
                label: "PASSWORD".to_string(),
                confidence: "high",
            },
        );
        assert_eq!((span.start, span.end), (10, 17));
    }
}
