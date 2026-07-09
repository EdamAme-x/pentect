use crate::config::ImageOcrConfig;
#[cfg(feature = "ocr")]
use crate::config::{image_ocr_config, ImageOcrMode, ImageRedactionStyle};
use pentect_core::model::labels;
use pentect_core::ByteRange;
use serde_json::Value;
#[cfg(feature = "ocr")]
use std::net::{IpAddr, SocketAddr};

#[cfg(feature = "ocr")]
const IMAGE_URL_MAX_REDIRECTS: usize = 5;
#[cfg(feature = "ocr")]
const IMAGE_METADATA_MAX_INFLATED_BYTES: u64 = 1024 * 1024;
const IMAGE_OBJECT_BYTE_FIELDS: &[&str] = &[
    "data",
    "bytes",
    "base64",
    "content",
    "image",
    "imageUrl",
    "image_url",
    "imageData",
    "image_data",
    "url",
    "uri",
    "src",
    "href",
    "dataUrl",
    "data_url",
];

pub(crate) struct ImageInspection {
    pub(crate) scanned_images: usize,
    pub(crate) unscanned_images: usize,
    pub(crate) ocr_failures: usize,
    pub(crate) secret_images: usize,
    attempted_images: usize,
    total_image_bytes: u64,
    started_at: std::time::Instant,
}

pub(crate) struct ImageRedaction {
    pub(crate) updated: Value,
    pub(crate) changed: bool,
    pub(crate) unscanned_images: usize,
    pub(crate) ocr_failures: usize,
    pub(crate) secret_images: usize,
    pub(crate) notes: Vec<String>,
}

struct ImageRedactionState {
    scanned_images: usize,
    unscanned_images: usize,
    ocr_failures: usize,
    secret_images: usize,
    attempted_images: usize,
    total_image_bytes: u64,
    started_at: std::time::Instant,
    notes: Vec<String>,
}

struct RedactedImagePayload {
    base64: String,
    data_url: String,
    mime_type: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct NormalizedImageRect {
    left: f32,
    top: f32,
    right: f32,
    bottom: f32,
}

#[derive(Clone, Debug)]
struct ImageTextRegion {
    text: String,
    rect: Option<NormalizedImageRect>,
}

#[derive(Clone, Debug)]
struct ImageSecretFinding {
    labels: Vec<String>,
    rect: Option<NormalizedImageRect>,
    force_black: bool,
    pad_left: bool,
    redact_pixels: bool,
}

#[derive(Clone, Debug)]
struct ImageTextSecretHit {
    label: String,
    range: Option<ByteRange>,
}

#[cfg(feature = "ocr")]
struct PngChunk<'a> {
    kind: &'a [u8],
    data: &'a [u8],
    range: std::ops::Range<usize>,
}

#[cfg(feature = "ocr")]
struct JpegApp1Segment<'a> {
    data: &'a [u8],
    range: std::ops::Range<usize>,
}

#[cfg(feature = "ocr")]
struct TextRedactionRange {
    range: ByteRange,
    tight_left: bool,
}

#[cfg(feature = "ocr")]
struct TextRedactionRect {
    rect: Option<NormalizedImageRect>,
    pad_left: bool,
}

enum ImageObjectEncoding {
    Base64,
    DataUrl,
}

struct ImageObjectSource {
    key: String,
    bytes: Vec<u8>,
    encoding: ImageObjectEncoding,
}

enum ImageRedactionDecision {
    Clean,
    Redacted(RedactedImagePayload),
}

pub(crate) fn contains_image_result(value: &Value) -> bool {
    match value {
        Value::String(text) => looks_like_image_reference(text) || looks_like_base64_image(text),
        Value::Number(_) | Value::Bool(_) | Value::Null => false,
        Value::Array(items) => items.iter().any(contains_image_result),
        Value::Object(map) => object_marks_image(map) || map.values().any(contains_image_result),
    }
}

pub(crate) fn skip_text_masking_for_image_payload(text: &str) -> bool {
    text.trim().to_ascii_lowercase().starts_with("data:image/") || looks_like_base64_image(text)
}

pub(crate) fn skip_text_masking_for_image_field(key: &str, text: &str) -> bool {
    if skip_text_masking_for_image_payload(text) {
        return true;
    }
    matches!(
        normalized_json_key(key).as_str(),
        "data" | "bytes" | "base64" | "content" | "imagedata" | "dataurl"
    )
}

pub(crate) fn inspect_tool_images_for_secrets(
    value: &Value,
    key: &[u8; 32],
    cfg: &ImageOcrConfig,
) -> Result<ImageInspection, String> {
    let mut inspection = ImageInspection {
        scanned_images: 0,
        unscanned_images: 0,
        ocr_failures: 0,
        secret_images: 0,
        attempted_images: 0,
        total_image_bytes: 0,
        started_at: std::time::Instant::now(),
    };
    collect_image_inspection(value, key, cfg, &mut inspection)?;
    Ok(inspection)
}

pub(crate) fn redact_tool_images_for_secrets(
    value: &Value,
    key: &[u8; 32],
    cfg: &ImageOcrConfig,
) -> Result<ImageRedaction, String> {
    let mut state = ImageRedactionState {
        scanned_images: 0,
        unscanned_images: 0,
        ocr_failures: 0,
        secret_images: 0,
        attempted_images: 0,
        total_image_bytes: 0,
        started_at: std::time::Instant::now(),
        notes: Vec::new(),
    };
    let updated = redact_image_value(value, key, cfg, &mut state)?;
    Ok(ImageRedaction {
        changed: updated != *value,
        updated,
        unscanned_images: state.unscanned_images,
        ocr_failures: state.ocr_failures,
        secret_images: state.secret_images,
        notes: state.notes,
    })
}

fn collect_image_inspection(
    value: &Value,
    key: &[u8; 32],
    cfg: &ImageOcrConfig,
    inspection: &mut ImageInspection,
) -> Result<(), String> {
    match value {
        Value::String(text) => {
            if looks_like_image_reference(text) || looks_like_base64_image(text) {
                if !inspection.reserve_image_slot(cfg) {
                    inspection.unscanned_images += 1;
                    return Ok(());
                }
                let Some(deadline) = inspection.deadline(cfg) else {
                    inspection.unscanned_images += 1;
                    return Ok(());
                };
                let Some(max_bytes) = inspection.remaining_image_bytes(cfg) else {
                    inspection.unscanned_images += 1;
                    return Ok(());
                };
                match image_reference_bytes(text, cfg, max_bytes, deadline) {
                    Ok(Some(bytes)) => inspect_image_bytes(&bytes, key, cfg, inspection),
                    Ok(None) | Err(_) => inspection.unscanned_images += 1,
                }
            }
        }
        Value::Number(_) | Value::Bool(_) | Value::Null => {}
        Value::Array(items) => {
            for item in items {
                collect_image_inspection(item, key, cfg, inspection)?;
            }
        }
        Value::Object(map) => {
            if object_marks_image(map) {
                if !inspection.reserve_image_slot(cfg) {
                    inspection.unscanned_images += 1;
                    return Ok(());
                }
                let Some(deadline) = inspection.deadline(cfg) else {
                    inspection.unscanned_images += 1;
                    return Ok(());
                };
                let Some(max_bytes) = inspection.remaining_image_bytes(cfg) else {
                    inspection.unscanned_images += 1;
                    return Ok(());
                };
                match image_object_bytes(map, cfg, max_bytes, deadline) {
                    Ok(Some(bytes)) => {
                        inspect_image_bytes(&bytes, key, cfg, inspection);
                        return Ok(());
                    }
                    Ok(None) | Err(_) => {
                        let before = inspection.total_observations();
                        for item in map.values() {
                            collect_image_inspection(item, key, cfg, inspection)?;
                        }
                        if !empty_image_object(map) && inspection.total_observations() == before {
                            inspection.unscanned_images += 1;
                        }
                    }
                }
                return Ok(());
            }
            for item in map.values() {
                collect_image_inspection(item, key, cfg, inspection)?;
            }
        }
    }
    Ok(())
}

fn inspect_image_bytes(
    bytes: &[u8],
    key: &[u8; 32],
    cfg: &ImageOcrConfig,
    inspection: &mut ImageInspection,
) {
    if !inspection.reserve_scan_bytes(bytes.len() as u64, cfg) {
        inspection.unscanned_images += 1;
        return;
    }
    inspection.scanned_images += 1;
    match image_secret_findings(bytes, key, cfg) {
        Ok(findings) if !findings.is_empty() => inspection.secret_images += 1,
        Ok(_) => {}
        Err(_) => inspection.ocr_failures += 1,
    }
}

impl ImageInspection {
    fn total_observations(&self) -> usize {
        self.scanned_images + self.unscanned_images + self.ocr_failures + self.secret_images
    }

    fn reserve_image_slot(&mut self, cfg: &ImageOcrConfig) -> bool {
        if self.attempted_images >= cfg.max_images {
            return false;
        }
        if self.started_at.elapsed() >= std::time::Duration::from_secs(cfg.max_seconds) {
            return false;
        }
        self.attempted_images += 1;
        true
    }

    fn reserve_scan_bytes(&mut self, bytes: u64, cfg: &ImageOcrConfig) -> bool {
        if bytes > cfg.max_image_bytes {
            return false;
        }
        let Some(total) = self.total_image_bytes.checked_add(bytes) else {
            return false;
        };
        if total > cfg.max_total_bytes {
            return false;
        }
        self.total_image_bytes = total;
        true
    }

    fn deadline(&self, cfg: &ImageOcrConfig) -> Option<std::time::Instant> {
        self.started_at
            .checked_add(std::time::Duration::from_secs(cfg.max_seconds))
    }

    fn remaining_image_bytes(&self, cfg: &ImageOcrConfig) -> Option<u64> {
        let remaining_total = cfg.max_total_bytes.checked_sub(self.total_image_bytes)?;
        let remaining = remaining_total.min(cfg.max_image_bytes);
        (remaining > 0).then_some(remaining)
    }
}

fn redact_image_value(
    value: &Value,
    key: &[u8; 32],
    cfg: &ImageOcrConfig,
    state: &mut ImageRedactionState,
) -> Result<Value, String> {
    match value {
        Value::String(text) => {
            if looks_like_image_reference(text) || looks_like_base64_image(text) {
                let Some(bytes) = reserve_and_read_image_reference(text, cfg, state)? else {
                    return Ok(value.clone());
                };
                return redact_image_bytes(&bytes, key, cfg, state)
                    .map(|decision| replace_string_image(value, decision));
            }
            Ok(value.clone())
        }
        Value::Number(_) | Value::Bool(_) | Value::Null => Ok(value.clone()),
        Value::Array(items) => {
            let mut changed = false;
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let updated = redact_image_value(item, key, cfg, state)?;
                changed |= updated != *item;
                out.push(updated);
            }
            if changed {
                Ok(Value::Array(out))
            } else {
                Ok(value.clone())
            }
        }
        Value::Object(map) => {
            if object_marks_image(map) {
                let before = state.total_observations();
                if let Some(updated) = redact_image_object_fields(value, map, key, cfg, state)? {
                    return Ok(updated);
                }
                let updated = redact_object_children(map, key, cfg, state)?;
                if !empty_image_object(map) && state.total_observations() == before {
                    state.unscanned_images += 1;
                }
                return Ok(updated.unwrap_or_else(|| value.clone()));
            }
            Ok(redact_object_children(map, key, cfg, state)?.unwrap_or_else(|| value.clone()))
        }
    }
}

fn redact_object_children(
    map: &serde_json::Map<String, Value>,
    key: &[u8; 32],
    cfg: &ImageOcrConfig,
    state: &mut ImageRedactionState,
) -> Result<Option<Value>, String> {
    let mut changed = false;
    let mut out = serde_json::Map::with_capacity(map.len());
    for (object_key, item) in map {
        let updated = redact_image_value(item, key, cfg, state)?;
        changed |= updated != *item;
        out.insert(object_key.clone(), updated);
    }
    Ok(changed.then_some(Value::Object(out)))
}

fn reserve_and_read_image_reference(
    text: &str,
    cfg: &ImageOcrConfig,
    state: &mut ImageRedactionState,
) -> Result<Option<Vec<u8>>, String> {
    if !state.reserve_image_slot(cfg) {
        state.unscanned_images += 1;
        return Ok(None);
    }
    let Some(deadline) = state.deadline(cfg) else {
        state.unscanned_images += 1;
        return Ok(None);
    };
    let Some(max_bytes) = state.remaining_image_bytes(cfg) else {
        state.unscanned_images += 1;
        return Ok(None);
    };
    match image_reference_bytes(text, cfg, max_bytes, deadline) {
        Ok(Some(bytes)) => Ok(Some(bytes)),
        Ok(None) | Err(_) => {
            state.unscanned_images += 1;
            Ok(None)
        }
    }
}

fn redact_image_object_fields(
    original: &Value,
    map: &serde_json::Map<String, Value>,
    key: &[u8; 32],
    cfg: &ImageOcrConfig,
    state: &mut ImageRedactionState,
) -> Result<Option<Value>, String> {
    let mut out = original
        .as_object()
        .cloned()
        .unwrap_or_else(serde_json::Map::new);
    let mut saw_image_field = false;
    let mut changed = false;
    for &field in IMAGE_OBJECT_BYTE_FIELDS {
        let Some(text) = map.get(field).and_then(Value::as_str) else {
            continue;
        };
        let Some(bytes) = reserve_and_read_image_reference(text, cfg, state)? else {
            continue;
        };
        saw_image_field = true;
        let source = ImageObjectSource {
            key: field.to_string(),
            bytes,
            encoding: image_object_field_encoding(field, text),
        };
        let decision = redact_image_bytes(&source.bytes, key, cfg, state)?;
        changed |= replace_object_image_field(&mut out, source, decision);
    }
    if !saw_image_field {
        return Ok(None);
    }
    if changed {
        Ok(Some(Value::Object(out)))
    } else {
        Ok(Some(original.clone()))
    }
}

fn image_object_field_encoding(key: &str, text: &str) -> ImageObjectEncoding {
    let normalized = normalized_json_key(key);
    if matches!(
        normalized.as_str(),
        "data" | "bytes" | "base64" | "content" | "imagedata"
    ) && !text.trim().to_ascii_lowercase().starts_with("data:image/")
    {
        ImageObjectEncoding::Base64
    } else {
        ImageObjectEncoding::DataUrl
    }
}

fn replace_string_image(original: &Value, decision: ImageRedactionDecision) -> Value {
    match decision {
        ImageRedactionDecision::Clean => original.clone(),
        ImageRedactionDecision::Redacted(payload) => Value::String(payload.data_url),
    }
}

fn replace_object_image_field(
    out: &mut serde_json::Map<String, Value>,
    source: ImageObjectSource,
    decision: ImageRedactionDecision,
) -> bool {
    let ImageRedactionDecision::Redacted(payload) = decision else {
        return false;
    };
    let replacement = match source.encoding {
        ImageObjectEncoding::Base64 => {
            set_image_mime_metadata(out, payload.mime_type);
            payload.base64
        }
        ImageObjectEncoding::DataUrl => payload.data_url,
    };
    out.insert(source.key, Value::String(replacement));
    true
}

fn set_image_mime_metadata(out: &mut serde_json::Map<String, Value>, mime_type: &'static str) {
    let mut updated_existing = false;
    for key in [
        "mimeType",
        "mimetype",
        "mime_type",
        "mediaType",
        "media_type",
        "contentType",
        "content_type",
    ] {
        if out.contains_key(key) {
            out.insert(key.to_string(), Value::String(mime_type.to_string()));
            updated_existing = true;
        }
    }
    if !updated_existing {
        out.insert("mimeType".to_string(), Value::String(mime_type.to_string()));
    }
}

fn redact_image_bytes(
    bytes: &[u8],
    key: &[u8; 32],
    cfg: &ImageOcrConfig,
    state: &mut ImageRedactionState,
) -> Result<ImageRedactionDecision, String> {
    if !state.reserve_scan_bytes(bytes.len() as u64, cfg) {
        state.unscanned_images += 1;
        return Ok(ImageRedactionDecision::Clean);
    }
    state.scanned_images += 1;

    let findings = match image_secret_findings(bytes, key, cfg) {
        Ok(findings) => findings,
        Err(_) => {
            state.ocr_failures += 1;
            Vec::new()
        }
    };
    if findings.is_empty() {
        return Ok(ImageRedactionDecision::Clean);
    }

    let mut labels = Vec::new();
    for finding in &findings {
        push_secret_labels(&mut labels, &finding.labels);
    }
    state.secret_images += 1;
    let index = state.notes.len() + 1;
    state.notes.push(format!("[{index}] {}", labels.join(", ")));
    let payload = redacted_image_payload(bytes, index, cfg, &findings)?;
    Ok(ImageRedactionDecision::Redacted(payload))
}

#[cfg(feature = "ocr")]
fn image_secret_findings(
    bytes: &[u8],
    key: &[u8; 32],
    cfg: &ImageOcrConfig,
) -> Result<Vec<ImageSecretFinding>, String> {
    let mut findings = Vec::new();
    for region in image_metadata_regions(bytes) {
        for hit in image_text_secret_hits(&region.text, key) {
            findings.push(ImageSecretFinding {
                labels: vec![hit.label.clone()],
                rect: None,
                force_black: false,
                pad_left: false,
                redact_pixels: false,
            });
        }
    }
    if image_exif_has_gps(bytes) {
        findings.push(ImageSecretFinding {
            labels: vec![labels::IMAGE_GPS_METADATA.to_string()],
            rect: None,
            force_black: false,
            pad_left: false,
            redact_pixels: false,
        });
    }

    for region in image_barcode_regions(bytes, cfg) {
        let labels = labels_from_text_hits(&image_text_secret_hits(&region.text, key));
        if labels.is_empty() {
            continue;
        }
        findings.push(ImageSecretFinding {
            labels,
            rect: region.rect,
            force_black: true,
            pad_left: true,
            redact_pixels: true,
        });
    }

    let ocr_regions = match ocr_image_regions_with_config(bytes, cfg) {
        Ok(regions) => regions,
        Err(err) if findings.is_empty() => return Err(err),
        Err(_) => return Ok(findings),
    };
    for region in &ocr_regions {
        for hit in image_text_secret_hits(&region.text, key) {
            let redaction = rect_for_text_secret_hit(region, &hit);
            findings.push(ImageSecretFinding {
                labels: vec![hit.label.clone()],
                rect: redaction.rect,
                force_black: false,
                pad_left: redaction.pad_left,
                redact_pixels: true,
            });
        }
    }
    let joined_labels = labels_from_text_hits(&image_text_secret_hits(
        &image_regions_text(&ocr_regions),
        key,
    ));
    let missing_joined_labels = joined_labels
        .into_iter()
        .filter(|label| {
            !findings
                .iter()
                .any(|finding| finding.labels.iter().any(|seen| seen == label))
        })
        .collect::<Vec<_>>();
    if !missing_joined_labels.is_empty() {
        findings.push(ImageSecretFinding {
            labels: missing_joined_labels,
            rect: union_region_rects(&ocr_regions),
            force_black: true,
            pad_left: true,
            redact_pixels: true,
        });
    }
    Ok(findings)
}

#[cfg(feature = "ocr")]
fn union_region_rects(regions: &[ImageTextRegion]) -> Option<NormalizedImageRect> {
    let mut out: Option<NormalizedImageRect> = None;
    for rect in regions.iter().filter_map(|region| region.rect) {
        out = Some(match out {
            Some(existing) => existing.union(rect),
            None => rect,
        });
    }
    out
}

#[cfg(not(feature = "ocr"))]
fn image_secret_findings(
    _bytes: &[u8],
    _key: &[u8; 32],
    cfg: &ImageOcrConfig,
) -> Result<Vec<ImageSecretFinding>, String> {
    if matches!(cfg.mode, crate::config::ImageOcrMode::Off) {
        Ok(Vec::new())
    } else {
        Err("image OCR requires a build with `--features ocr`".to_string())
    }
}

fn push_secret_labels(out: &mut Vec<String>, labels: &[String]) {
    for label in labels {
        if !out.iter().any(|seen| seen == label) {
            out.push(label.clone());
        }
    }
}

impl ImageRedactionState {
    fn total_observations(&self) -> usize {
        self.scanned_images + self.unscanned_images + self.ocr_failures + self.secret_images
    }

    fn reserve_image_slot(&mut self, cfg: &ImageOcrConfig) -> bool {
        if self.attempted_images >= cfg.max_images {
            return false;
        }
        if self.started_at.elapsed() >= std::time::Duration::from_secs(cfg.max_seconds) {
            return false;
        }
        self.attempted_images += 1;
        true
    }

    fn reserve_scan_bytes(&mut self, bytes: u64, cfg: &ImageOcrConfig) -> bool {
        if bytes > cfg.max_image_bytes {
            return false;
        }
        let Some(total) = self.total_image_bytes.checked_add(bytes) else {
            return false;
        };
        if total > cfg.max_total_bytes {
            return false;
        }
        self.total_image_bytes = total;
        true
    }

    fn deadline(&self, cfg: &ImageOcrConfig) -> Option<std::time::Instant> {
        self.started_at
            .checked_add(std::time::Duration::from_secs(cfg.max_seconds))
    }

    fn remaining_image_bytes(&self, cfg: &ImageOcrConfig) -> Option<u64> {
        let remaining_total = cfg.max_total_bytes.checked_sub(self.total_image_bytes)?;
        let remaining = remaining_total.min(cfg.max_image_bytes);
        (remaining > 0).then_some(remaining)
    }
}

fn image_regions_text(regions: &[ImageTextRegion]) -> String {
    let mut text = String::new();
    for region in regions {
        if region.text.trim().is_empty() {
            continue;
        }
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&region.text);
    }
    text
}

#[cfg(feature = "ocr")]
fn image_metadata_regions(bytes: &[u8]) -> Vec<ImageTextRegion> {
    let mut texts = Vec::new();
    collect_jpeg_metadata_text(bytes, &mut texts);
    collect_png_metadata_text(bytes, &mut texts);
    texts.sort();
    texts.dedup();
    texts
        .into_iter()
        .filter(|text| !text.trim().is_empty())
        .map(|text| ImageTextRegion { text, rect: None })
        .collect()
}

#[cfg(feature = "ocr")]
fn collect_jpeg_metadata_text(bytes: &[u8], out: &mut Vec<String>) {
    for segment in jpeg_app1_segments(bytes) {
        if let Some(tiff) = segment.strip_prefix(b"Exif\0\0") {
            collect_printable_metadata_strings(tiff, out);
        } else if let Some(xmp) = segment.strip_prefix(b"http://ns.adobe.com/xap/1.0/\0") {
            if let Ok(text) = std::str::from_utf8(xmp) {
                out.push(text.to_string());
            }
        }
    }
}

#[cfg(feature = "ocr")]
fn collect_png_metadata_text(bytes: &[u8], out: &mut Vec<String>) {
    for chunk in png_chunks(bytes) {
        match chunk.kind {
            b"tEXt" => collect_png_text_chunk(chunk.data, out),
            b"zTXt" => collect_png_ztxt_chunk(chunk.data, out),
            b"iTXt" => collect_png_itxt_chunk(chunk.data, out),
            b"eXIf" => collect_printable_metadata_strings(chunk.data, out),
            _ => {}
        }
    }
}

#[cfg(feature = "ocr")]
fn png_chunks(bytes: &[u8]) -> Vec<PngChunk<'_>> {
    const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    if !bytes.starts_with(PNG_SIGNATURE) {
        return Vec::new();
    }
    let mut chunks = Vec::new();
    let mut offset = 8usize;
    while offset.saturating_add(12) <= bytes.len() {
        let Some(len) = read_be_u32(bytes, offset).and_then(|len| usize::try_from(len).ok()) else {
            break;
        };
        let kind_start = offset + 4;
        let data_start = kind_start + 4;
        let Some(data_end) = data_start.checked_add(len) else {
            break;
        };
        let Some(next) = data_end.checked_add(4) else {
            break;
        };
        if next > bytes.len() {
            break;
        }
        let kind = &bytes[kind_start..data_start];
        if kind == b"IEND" {
            break;
        }
        chunks.push(PngChunk {
            kind,
            data: &bytes[data_start..data_end],
            range: offset..next,
        });
        offset = next;
    }
    chunks
}

#[cfg(feature = "ocr")]
fn collect_png_text_chunk(data: &[u8], out: &mut Vec<String>) {
    let Some(split) = data.iter().position(|&b| b == 0) else {
        return;
    };
    let key = lossy_metadata_text(&data[..split]);
    let value = lossy_metadata_text(&data[split + 1..]);
    push_metadata_line(out, &key, &value);
}

#[cfg(feature = "ocr")]
fn collect_png_ztxt_chunk(data: &[u8], out: &mut Vec<String>) {
    let Some(key_end) = data.iter().position(|&b| b == 0) else {
        return;
    };
    let method = data.get(key_end + 1).copied();
    if method != Some(0) {
        return;
    }
    let Some(compressed) = data.get(key_end + 2..) else {
        return;
    };
    let Some(value_bytes) = inflate_png_metadata_text(compressed) else {
        return;
    };
    let key = lossy_metadata_text(&data[..key_end]);
    let value = lossy_metadata_text(&value_bytes);
    push_metadata_line(out, &key, &value);
}

#[cfg(feature = "ocr")]
fn collect_png_itxt_chunk(data: &[u8], out: &mut Vec<String>) {
    let Some(key_end) = data.iter().position(|&b| b == 0) else {
        return;
    };
    let mut cursor = key_end + 1;
    if cursor + 2 > data.len() {
        return;
    }
    let compression_flag = data[cursor];
    let compression_method = data[cursor + 1];
    cursor += 2;
    let Some(lang_end) = data[cursor..].iter().position(|&b| b == 0) else {
        return;
    };
    cursor += lang_end + 1;
    let Some(translated_end) = data[cursor..].iter().position(|&b| b == 0) else {
        return;
    };
    cursor += translated_end + 1;
    let key = lossy_metadata_text(&data[..key_end]);
    let value_bytes = match compression_flag {
        0 => data[cursor..].to_vec(),
        1 if compression_method == 0 => match inflate_png_metadata_text(&data[cursor..]) {
            Some(value) => value,
            None => return,
        },
        _ => return,
    };
    let value = lossy_metadata_text(&value_bytes);
    push_metadata_line(out, &key, &value);
}

#[cfg(feature = "ocr")]
fn inflate_png_metadata_text(data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;

    let decoder = flate2::read::ZlibDecoder::new(data);
    let mut limited = decoder.take(IMAGE_METADATA_MAX_INFLATED_BYTES + 1);
    let mut out = Vec::new();
    limited.read_to_end(&mut out).ok()?;
    (out.len() as u64 <= IMAGE_METADATA_MAX_INFLATED_BYTES).then_some(out)
}

#[cfg(feature = "ocr")]
fn collect_printable_metadata_strings(bytes: &[u8], out: &mut Vec<String>) {
    for text in printable_ascii_strings(bytes, 6) {
        out.push(text);
    }
    for text in printable_utf16_strings(bytes, 6, Endian::Little) {
        out.push(text);
    }
    for text in printable_utf16_strings(bytes, 6, Endian::Big) {
        out.push(text);
    }
}

#[cfg(feature = "ocr")]
fn printable_ascii_strings(bytes: &[u8], min_chars: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = None;
    for (idx, &byte) in bytes.iter().enumerate() {
        if byte.is_ascii_graphic() || byte == b' ' || byte == b'\t' {
            start.get_or_insert(idx);
            continue;
        }
        if let Some(s) = take_printable_ascii(bytes, start.take(), idx, min_chars) {
            out.push(s);
        }
    }
    if let Some(s) = take_printable_ascii(bytes, start, bytes.len(), min_chars) {
        out.push(s);
    }
    out
}

#[cfg(feature = "ocr")]
fn take_printable_ascii(
    bytes: &[u8],
    start: Option<usize>,
    end: usize,
    min_chars: usize,
) -> Option<String> {
    let start = start?;
    let slice = bytes.get(start..end)?;
    let text = std::str::from_utf8(slice).ok()?.trim();
    (text.chars().count() >= min_chars).then(|| text.to_string())
}

#[cfg(feature = "ocr")]
fn printable_utf16_strings(bytes: &[u8], min_chars: usize, endian: Endian) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = Vec::new();
    let mut chunks = bytes.chunks_exact(2);
    for pair in &mut chunks {
        let unit = match endian {
            Endian::Little => u16::from_le_bytes([pair[0], pair[1]]),
            Endian::Big => u16::from_be_bytes([pair[0], pair[1]]),
        };
        let Some(ch) = char::from_u32(u32::from(unit)) else {
            flush_utf16_string(&mut current, min_chars, &mut out);
            continue;
        };
        if ch.is_ascii_graphic() || ch == ' ' || ch == '\t' {
            current.push(ch);
        } else {
            flush_utf16_string(&mut current, min_chars, &mut out);
        }
    }
    flush_utf16_string(&mut current, min_chars, &mut out);
    out
}

#[cfg(feature = "ocr")]
fn flush_utf16_string(current: &mut Vec<char>, min_chars: usize, out: &mut Vec<String>) {
    if current.len() >= min_chars {
        let text = current.iter().collect::<String>();
        let text = text.trim();
        if text.chars().count() >= min_chars {
            out.push(text.to_string());
        }
    }
    current.clear();
}

#[cfg(feature = "ocr")]
fn lossy_metadata_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_string()
}

#[cfg(feature = "ocr")]
fn push_metadata_line(out: &mut Vec<String>, key: &str, value: &str) {
    if key.is_empty() && value.is_empty() {
        return;
    }
    if key.is_empty() {
        out.push(value.to_string());
    } else if value.is_empty() {
        out.push(key.to_string());
    } else {
        out.push(format!("{key}: {value}"));
    }
}

#[cfg(feature = "ocr")]
fn image_exif_has_gps(bytes: &[u8]) -> bool {
    jpeg_exif_has_gps(bytes) || png_exif_has_gps(bytes)
}

#[cfg(feature = "ocr")]
fn jpeg_exif_has_gps(bytes: &[u8]) -> bool {
    jpeg_app1_segments(bytes)
        .iter()
        .filter_map(|segment| segment.strip_prefix(b"Exif\0\0"))
        .any(tiff_has_gps_ifd)
}

#[cfg(feature = "ocr")]
fn png_exif_has_gps(bytes: &[u8]) -> bool {
    for chunk in png_chunks(bytes) {
        if chunk.kind == b"eXIf" && tiff_has_gps_ifd(chunk.data) {
            return true;
        }
    }
    false
}

#[cfg(feature = "ocr")]
fn jpeg_app1_segments(bytes: &[u8]) -> Vec<&[u8]> {
    jpeg_app1_segment_items(bytes)
        .into_iter()
        .map(|segment| segment.data)
        .collect()
}

#[cfg(feature = "ocr")]
fn jpeg_app1_segment_ranges(bytes: &[u8]) -> Vec<std::ops::Range<usize>> {
    jpeg_app1_segment_items(bytes)
        .into_iter()
        .map(|segment| segment.range)
        .collect()
}

#[cfg(feature = "ocr")]
fn jpeg_app1_segment_items(bytes: &[u8]) -> Vec<JpegApp1Segment<'_>> {
    if !bytes.starts_with(b"\xff\xd8") {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut offset = 2usize;
    while offset + 4 <= bytes.len() {
        if bytes[offset] != 0xff {
            break;
        }
        let marker_start = offset;
        while offset < bytes.len() && bytes[offset] == 0xff {
            offset += 1;
        }
        if offset >= bytes.len() {
            break;
        }
        let marker = bytes[offset];
        offset += 1;
        if marker == 0xd9 || marker == 0xda {
            break;
        }
        if marker == 0x01 || (0xd0..=0xd7).contains(&marker) {
            continue;
        }
        if offset + 2 > bytes.len() {
            break;
        }
        let Some(len) = read_be_u16(bytes, offset).map(usize::from) else {
            break;
        };
        if len < 2 {
            break;
        }
        let data_start = offset + 2;
        let Some(data_end) = offset.checked_add(len) else {
            break;
        };
        if data_end > bytes.len() {
            break;
        }
        if marker == 0xe1 {
            out.push(JpegApp1Segment {
                data: &bytes[data_start..data_end],
                range: marker_start..data_end,
            });
        }
        offset = data_end;
    }
    out
}

#[cfg(feature = "ocr")]
fn tiff_has_gps_ifd(tiff: &[u8]) -> bool {
    if tiff.len() < 8 {
        return false;
    }
    let endian = match tiff.get(0..2) {
        Some(b"II") => Endian::Little,
        Some(b"MM") => Endian::Big,
        _ => return false,
    };
    if read_u16(tiff, 2, endian) != Some(42) {
        return false;
    }
    let Some(ifd0) = read_u32(tiff, 4, endian).and_then(|v| usize::try_from(v).ok()) else {
        return false;
    };
    ifd_has_tag(tiff, ifd0, endian, 0x8825)
}

#[cfg(feature = "ocr")]
fn ifd_has_tag(tiff: &[u8], offset: usize, endian: Endian, tag: u16) -> bool {
    let Some(count) = read_u16(tiff, offset, endian).map(usize::from) else {
        return false;
    };
    let mut entry = offset.saturating_add(2);
    for _ in 0..count {
        if entry.saturating_add(12) > tiff.len() {
            return false;
        }
        if read_u16(tiff, entry, endian) == Some(tag) {
            return true;
        }
        entry += 12;
    }
    false
}

#[cfg(feature = "ocr")]
#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

#[cfg(feature = "ocr")]
fn read_be_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset + 2)?;
    Some(u16::from_be_bytes([slice[0], slice[1]]))
}

#[cfg(feature = "ocr")]
fn read_be_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[cfg(feature = "ocr")]
fn read_u16(bytes: &[u8], offset: usize, endian: Endian) -> Option<u16> {
    let slice = bytes.get(offset..offset + 2)?;
    Some(match endian {
        Endian::Little => u16::from_le_bytes([slice[0], slice[1]]),
        Endian::Big => u16::from_be_bytes([slice[0], slice[1]]),
    })
}

#[cfg(feature = "ocr")]
fn read_u32(bytes: &[u8], offset: usize, endian: Endian) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(match endian {
        Endian::Little => u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]),
        Endian::Big => u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]),
    })
}

#[cfg(feature = "ocr")]
fn rect_for_text_secret_hit(
    region: &ImageTextRegion,
    hit: &ImageTextSecretHit,
) -> TextRedactionRect {
    let Some(base) = region.rect else {
        return TextRedactionRect {
            rect: None,
            pad_left: true,
        };
    };
    let Some(redaction) = redaction_text_range(&region.text, hit.range) else {
        return TextRedactionRect {
            rect: region.rect,
            pad_left: true,
        };
    };
    TextRedactionRect {
        rect: text_range_to_rect(base, &region.text, redaction.range).or(region.rect),
        pad_left: !redaction.tight_left,
    }
}

#[cfg(feature = "ocr")]
fn redaction_text_range(text: &str, range: Option<ByteRange>) -> Option<TextRedactionRange> {
    match range {
        Some(range) => match assignment_value_range_for_span(text, range) {
            Some(range) => Some(TextRedactionRange {
                range,
                tight_left: true,
            }),
            None => Some(TextRedactionRange {
                range,
                tight_left: false,
            }),
        },
        None => first_sensitive_assignment_value_range(text).map(|range| TextRedactionRange {
            range,
            tight_left: true,
        }),
    }
}

#[cfg(feature = "ocr")]
fn text_range_to_rect(
    rect: NormalizedImageRect,
    text: &str,
    range: ByteRange,
) -> Option<NormalizedImageRect> {
    let total_chars = text.chars().count();
    if total_chars == 0 {
        return None;
    }
    let start = byte_to_char_count(text, range.start.min(text.len()));
    let end = byte_to_char_count(text, range.end.min(text.len())).max(start + 1);
    if end <= start {
        return None;
    }
    let width = rect.right - rect.left;
    let left = rect.left + width * (start as f32 / total_chars as f32);
    let right = rect.left + width * (end as f32 / total_chars as f32);
    NormalizedImageRect::new(left, rect.top, right, rect.bottom)
}

#[cfg(feature = "ocr")]
fn byte_to_char_count(text: &str, byte: usize) -> usize {
    let end = floor_char_boundary(text, byte.min(text.len()));
    text[..end].chars().count()
}

fn floor_char_boundary(text: &str, mut byte: usize) -> usize {
    while byte > 0 && !text.is_char_boundary(byte) {
        byte -= 1;
    }
    byte
}

fn assignment_value_range_for_span(text: &str, range: ByteRange) -> Option<ByteRange> {
    if range.start >= text.len() || range.end <= range.start {
        return None;
    }
    let (line_start, line_end) = text_line_bounds(text, range.start);
    if range.end > line_end {
        return None;
    }
    let mut out = None;
    let search_end = range.end.min(line_end);
    for (rel, ch) in text[line_start..search_end].char_indices() {
        if ch != '=' && ch != ':' {
            continue;
        }
        let sep = line_start + rel;
        let Some(value) = sensitive_assignment_value_range(text, line_start, line_end, sep, None)
        else {
            continue;
        };
        out = Some(value);
    }
    out
}

fn first_sensitive_assignment_value_range(text: &str) -> Option<ByteRange> {
    for (idx, ch) in text.char_indices() {
        if ch != '=' && ch != ':' {
            continue;
        }
        let (line_start, line_end) = text_line_bounds(text, idx);
        if let Some(range) = sensitive_assignment_value_range(text, line_start, line_end, idx, None)
        {
            return Some(range);
        }
    }
    None
}

fn sensitive_assignment_value_range(
    text: &str,
    line_start: usize,
    line_end: usize,
    sep: usize,
    end_hint: Option<usize>,
) -> Option<ByteRange> {
    if !(line_start <= sep && sep < line_end) {
        return None;
    }
    let key_tokens = ocr_words(&text[line_start..sep]);
    if !ocr_words_have_sensitive_key(&key_tokens) {
        return None;
    }
    let sep_ch = text[sep..].chars().next()?;
    let value_start = trim_ascii_ws_start(text, sep + sep_ch.len_utf8(), line_end);
    let end_limit = end_hint.unwrap_or(line_end).min(line_end).max(value_start);
    let value_end = trim_ascii_ws_end(text, value_start, end_limit);
    (value_end > value_start).then_some(ByteRange::new(value_start, value_end))
}

fn text_line_bounds(text: &str, byte: usize) -> (usize, usize) {
    let byte = floor_char_boundary(text, byte.min(text.len()));
    let start = text[..byte].rfind(['\r', '\n']).map_or(0, |idx| idx + 1);
    let end = text[byte..]
        .find(['\r', '\n'])
        .map_or(text.len(), |offset| byte + offset);
    (start, end)
}

fn trim_ascii_ws_start(text: &str, mut start: usize, end: usize) -> usize {
    start = floor_char_boundary(text, start.min(text.len()));
    let end = floor_char_boundary(text, end.min(text.len()));
    while start < end && text.as_bytes()[start].is_ascii_whitespace() {
        start += 1;
    }
    start
}

fn trim_ascii_ws_end(text: &str, start: usize, mut end: usize) -> usize {
    let start = floor_char_boundary(text, start.min(text.len()));
    end = floor_char_boundary(text, end.min(text.len()));
    while start < end && text.as_bytes()[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    end
}

#[cfg(test)]
fn image_text_secret_labels(text: &str, key: &[u8; 32]) -> Vec<String> {
    labels_from_text_hits(&image_text_secret_hits(text, key))
}

fn image_text_secret_hits(text: &str, _key: &[u8; 32]) -> Vec<ImageTextSecretHit> {
    if text.trim().is_empty() {
        return Vec::new();
    }
    let engine = image_ocr_secret_engine();
    let result = engine.analyze_spans(pentect_core::Input {
        kind: pentect_core::Kind::Text,
        data: text.to_string(),
    });
    let mut hits = Vec::new();
    for span in result.spans {
        if !hits.iter().any(|seen: &ImageTextSecretHit| {
            seen.label == span.label && seen.range == Some(span.range)
        }) {
            hits.push(ImageTextSecretHit {
                label: span.label,
                range: Some(span.range),
            });
        }
    }
    for hit in ocr_fragmented_secret_hits(text) {
        if !hits
            .iter()
            .any(|seen| seen.label == hit.label && seen.range == hit.range)
        {
            hits.push(hit);
        }
    }
    hits
}

fn labels_from_text_hits(hits: &[ImageTextSecretHit]) -> Vec<String> {
    let mut labels = Vec::new();
    for hit in hits {
        if !labels.iter().any(|seen| seen == &hit.label) {
            labels.push(hit.label.clone());
        }
    }
    labels
}

#[cfg(test)]
fn ocr_fragmented_secret_labels(text: &str) -> Vec<String> {
    labels_from_text_hits(&ocr_fragmented_secret_hits(text))
}

fn ocr_fragmented_secret_hits(text: &str) -> Vec<ImageTextSecretHit> {
    let mut labels = Vec::new();
    for (idx, ch) in text.char_indices() {
        if ch != '=' && ch != ':' {
            continue;
        }
        let (line_start, line_end) = text_line_bounds(text, idx);
        let before = bounded_prefix(&text[line_start..idx], idx - line_start, 96);
        let after_start = idx + ch.len_utf8();
        let after = bounded_suffix(&text[after_start..line_end], 128);
        let Some(label) = ocr_fragmented_secret_label(before, after) else {
            continue;
        };
        let range = sensitive_assignment_value_range(text, line_start, line_end, idx, None);
        if !labels
            .iter()
            .any(|seen: &ImageTextSecretHit| seen.label == label && seen.range == range)
        {
            labels.push(ImageTextSecretHit { label, range });
        }
    }
    labels
}

fn ocr_fragmented_secret_label(before: &str, after: &str) -> Option<String> {
    let key_tokens = ocr_words(before);
    if !ocr_words_have_sensitive_key(&key_tokens) || !ocr_fragmented_value_has_secret_shape(after) {
        return None;
    }
    Some(ocr_key_label(&key_tokens))
}

fn bounded_prefix(text: &str, byte_end: usize, max_chars: usize) -> &str {
    let end = byte_end.min(text.len());
    let mut starts = text[..end].char_indices().map(|(idx, _)| idx).rev();
    let start = starts.nth(max_chars.saturating_sub(1)).unwrap_or(0);
    &text[start..end]
}

fn bounded_suffix(text: &str, max_chars: usize) -> &str {
    match text.char_indices().nth(max_chars) {
        Some((idx, _)) => &text[..idx],
        None => text,
    }
}

fn ocr_words(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            current.push(ch.to_ascii_uppercase());
        } else if !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn ocr_words_have_sensitive_key(words: &[String]) -> bool {
    let mut has_material = false;
    let mut has_modifier = false;
    for word in words {
        match word.as_str() {
            "PASSWORD" | "PASSWD" | "PWD" | "SECRET" | "TOKEN" | "CREDENTIAL" | "CREDENTIALS" => {
                has_material = true;
            }
            "KEY" => {
                has_material = true;
            }
            "API" | "ACCESS" | "AUTH" | "PRIVATE" | "CLIENT" => {
                has_modifier = true;
            }
            _ => {}
        }
    }
    has_material
        && (has_modifier
            || words
                .iter()
                .last()
                .is_some_and(|word| matches!(word.as_str(), "PASSWORD" | "SECRET" | "TOKEN")))
}

fn ocr_fragmented_value_has_secret_shape(text: &str) -> bool {
    let mut ascii_alnum = 0usize;
    let mut ascii_alpha = 0usize;
    let mut ascii_digit = 0usize;
    let mut longest_run = 0usize;
    let mut run = 0usize;
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            ascii_alnum += 1;
            if ch.is_ascii_alphabetic() {
                ascii_alpha += 1;
            }
            if ch.is_ascii_digit() {
                ascii_digit += 1;
            }
            run += 1;
            longest_run = longest_run.max(run);
        } else {
            run = 0;
        }
    }
    ascii_alnum >= 16 && ascii_alpha >= 4 && ascii_digit >= 4 && longest_run >= 6
}

fn ocr_key_label(words: &[String]) -> String {
    let mut relevant = words
        .iter()
        .rev()
        .filter(|word| word.len() <= 32)
        .take(3)
        .map(String::as_str)
        .collect::<Vec<_>>();
    relevant.reverse();
    if relevant.is_empty() {
        labels::KEYED_SECRET.to_string()
    } else {
        relevant.join("_")
    }
}

impl NormalizedImageRect {
    #[cfg(feature = "ocr")]
    fn from_pixels(
        left: f32,
        top: f32,
        width: f32,
        height: f32,
        image_width: u32,
        image_height: u32,
    ) -> Option<Self> {
        if image_width == 0 || image_height == 0 || width <= 0.0 || height <= 0.0 {
            return None;
        }
        let image_width = image_width as f32;
        let image_height = image_height as f32;
        Self::new(
            left / image_width,
            top / image_height,
            (left + width) / image_width,
            (top + height) / image_height,
        )
    }

    #[cfg(feature = "ocr")]
    fn from_points(points: &[rxing::Point], image_width: u32, image_height: u32) -> Option<Self> {
        if points.is_empty() || image_width == 0 || image_height == 0 {
            return None;
        }
        let mut left = f32::MAX;
        let mut top = f32::MAX;
        let mut right = f32::MIN;
        let mut bottom = f32::MIN;
        for point in points {
            left = left.min(point.x);
            top = top.min(point.y);
            right = right.max(point.x);
            bottom = bottom.max(point.y);
        }
        Self::from_pixels(
            left,
            top,
            right - left,
            bottom - top,
            image_width,
            image_height,
        )
    }

    #[cfg(all(feature = "ocr", target_os = "macos"))]
    fn from_macos_vision_rect(rect: objc2_core_foundation::CGRect) -> Option<Self> {
        let left = rect.origin.x as f32;
        let width = rect.size.width as f32;
        let height = rect.size.height as f32;
        if width <= 0.0 || height <= 0.0 {
            return None;
        }
        let bottom_from_vision = rect.origin.y as f32;
        let top = 1.0 - bottom_from_vision - height;
        Self::new(left, top, left + width, top + height)
    }

    #[cfg(feature = "ocr")]
    fn new(left: f32, top: f32, right: f32, bottom: f32) -> Option<Self> {
        if !left.is_finite() || !top.is_finite() || !right.is_finite() || !bottom.is_finite() {
            return None;
        }
        let left = left.clamp(0.0, 1.0);
        let top = top.clamp(0.0, 1.0);
        let right = right.clamp(0.0, 1.0);
        let bottom = bottom.clamp(0.0, 1.0);
        (right > left && bottom > top).then_some(Self {
            left,
            top,
            right,
            bottom,
        })
    }

    #[cfg(feature = "ocr")]
    fn to_pixels(self, image_width: u32, image_height: u32) -> Option<PixelRect> {
        if image_width == 0 || image_height == 0 {
            return None;
        }
        let left = (self.left * image_width as f32).floor().max(0.0) as u32;
        let top = (self.top * image_height as f32).floor().max(0.0) as u32;
        let right = (self.right * image_width as f32)
            .ceil()
            .min(image_width as f32) as u32;
        let bottom = (self.bottom * image_height as f32)
            .ceil()
            .min(image_height as f32) as u32;
        (right > left && bottom > top).then_some(PixelRect {
            left,
            top,
            width: right - left,
            height: bottom - top,
        })
    }

    #[cfg(feature = "ocr")]
    fn union(self, other: Self) -> Self {
        Self {
            left: self.left.min(other.left),
            top: self.top.min(other.top),
            right: self.right.max(other.right),
            bottom: self.bottom.max(other.bottom),
        }
    }
}

#[cfg(feature = "ocr")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PixelRect {
    left: u32,
    top: u32,
    width: u32,
    height: u32,
}

#[cfg(feature = "ocr")]
fn redacted_image_payload(
    bytes: &[u8],
    index: usize,
    cfg: &ImageOcrConfig,
    findings: &[ImageSecretFinding],
) -> Result<RedactedImagePayload, String> {
    use image::{GenericImageView, ImageFormat};
    use std::io::Cursor;

    let metadata_only = findings.iter().all(|finding| !finding.redact_pixels);
    if metadata_only {
        return stripped_metadata_image_payload(bytes)
            .ok_or_else(|| "could not strip image metadata safely".to_string());
    }

    let image =
        image::load_from_memory(bytes).map_err(|e| format!("could not decode image: {e}"))?;
    let source_dimensions = image.dimensions();
    let pixels = u64::from(source_dimensions.0).saturating_mul(u64::from(source_dimensions.1));
    if pixels > cfg.max_pixels {
        return Err(format!(
            "image has {pixels} pixels; limit is {}",
            cfg.max_pixels
        ));
    }
    let (width, height) = redacted_image_dimensions(source_dimensions, cfg.max_edge);
    let mut redacted = image
        .resize_exact(width, height, image::imageops::FilterType::Triangle)
        .to_rgba8();
    for finding in findings {
        if !finding.redact_pixels {
            continue;
        }
        let style = if finding.force_black {
            ImageRedactionStyle::Black
        } else {
            cfg.redaction
        };
        apply_local_redaction(&mut redacted, finding.rect, style, finding.pad_left, index);
    }

    let mut png = Vec::new();
    image::DynamicImage::ImageRgba8(redacted)
        .write_to(&mut Cursor::new(&mut png), ImageFormat::Png)
        .map_err(|e| format!("could not encode redacted image: {e}"))?;
    let base64 = data_encoding::BASE64.encode(&png);
    Ok(RedactedImagePayload {
        data_url: format!("data:image/png;base64,{base64}"),
        base64,
        mime_type: "image/png",
    })
}

#[cfg(feature = "ocr")]
fn stripped_metadata_image_payload(bytes: &[u8]) -> Option<RedactedImagePayload> {
    let (stripped, mime_type) = strip_image_metadata(bytes)?;
    Some(redacted_payload_from_bytes(stripped, mime_type))
}

#[cfg(feature = "ocr")]
fn redacted_payload_from_bytes(bytes: Vec<u8>, mime_type: &'static str) -> RedactedImagePayload {
    let base64 = data_encoding::BASE64.encode(&bytes);
    RedactedImagePayload {
        data_url: format!("data:{mime_type};base64,{base64}"),
        base64,
        mime_type,
    }
}

#[cfg(feature = "ocr")]
fn strip_image_metadata(bytes: &[u8]) -> Option<(Vec<u8>, &'static str)> {
    match image_signature(bytes) {
        Some("jpeg") => strip_jpeg_app1_segments(bytes).map(|bytes| (bytes, "image/jpeg")),
        Some("png") => strip_png_metadata_chunks(bytes).map(|bytes| (bytes, "image/png")),
        _ => None,
    }
}

#[cfg(feature = "ocr")]
fn strip_jpeg_app1_segments(bytes: &[u8]) -> Option<Vec<u8>> {
    let ranges = jpeg_app1_segment_ranges(bytes);
    (!ranges.is_empty()).then(|| strip_byte_ranges(bytes, &ranges))
}

#[cfg(feature = "ocr")]
fn strip_png_metadata_chunks(bytes: &[u8]) -> Option<Vec<u8>> {
    let ranges = png_chunks(bytes)
        .into_iter()
        .filter(|chunk| matches!(chunk.kind, b"tEXt" | b"iTXt" | b"zTXt" | b"eXIf"))
        .map(|chunk| chunk.range)
        .collect::<Vec<_>>();
    (!ranges.is_empty()).then(|| strip_byte_ranges(bytes, &ranges))
}

#[cfg(feature = "ocr")]
fn strip_byte_ranges(bytes: &[u8], ranges: &[std::ops::Range<usize>]) -> Vec<u8> {
    let removed = ranges
        .iter()
        .map(|range| range.end.saturating_sub(range.start))
        .sum::<usize>();
    let mut out = Vec::with_capacity(bytes.len().saturating_sub(removed));
    let mut cursor = 0usize;
    for range in ranges {
        if range.start < cursor || range.end > bytes.len() {
            continue;
        }
        out.extend_from_slice(&bytes[cursor..range.start]);
        cursor = range.end;
    }
    out.extend_from_slice(&bytes[cursor..]);
    out
}

#[cfg(not(feature = "ocr"))]
fn redacted_image_payload(
    _bytes: &[u8],
    _index: usize,
    _cfg: &ImageOcrConfig,
    _findings: &[ImageSecretFinding],
) -> Result<RedactedImagePayload, String> {
    Err("image OCR requires a build with `--features ocr`".to_string())
}

#[cfg(feature = "ocr")]
fn apply_local_redaction(
    image: &mut image::RgbaImage,
    rect: Option<NormalizedImageRect>,
    style: ImageRedactionStyle,
    pad_left: bool,
    _index: usize,
) {
    let Some(rect) = rect
        .or_else(|| NormalizedImageRect::new(0.0, 0.0, 1.0, 1.0))
        .and_then(|rect| padded_pixel_rect(rect, image.width(), image.height(), pad_left))
    else {
        return;
    };
    match style {
        ImageRedactionStyle::Black => fill_rect(
            image,
            rect.left,
            rect.top,
            rect.width,
            rect.height,
            image::Rgba([0, 0, 0, 255]),
        ),
        ImageRedactionStyle::Blur => blur_rect(image, rect),
    }
}

#[cfg(feature = "ocr")]
fn padded_pixel_rect(
    rect: NormalizedImageRect,
    image_width: u32,
    image_height: u32,
    pad_left: bool,
) -> Option<PixelRect> {
    let rect = rect.to_pixels(image_width, image_height)?;
    let pad_x = rect.width.saturating_div(10).clamp(16, 96);
    let pad_y = rect.height.saturating_div(2).clamp(8, 32);
    let left = if pad_left {
        rect.left.saturating_sub(pad_x)
    } else {
        rect.left
    };
    let top = rect.top.saturating_sub(pad_y);
    let right = rect
        .left
        .saturating_add(rect.width)
        .saturating_add(pad_x)
        .min(image_width);
    let bottom = rect
        .top
        .saturating_add(rect.height)
        .saturating_add(pad_y)
        .min(image_height);
    (right > left && bottom > top).then_some(PixelRect {
        left,
        top,
        width: right - left,
        height: bottom - top,
    })
}

#[cfg(feature = "ocr")]
fn blur_rect(image: &mut image::RgbaImage, rect: PixelRect) {
    use image::imageops::FilterType;

    let crop =
        image::imageops::crop_imm(image, rect.left, rect.top, rect.width, rect.height).to_image();
    let tiny_width = rect.width.saturating_div(24).clamp(1, 16);
    let tiny_height = rect.height.saturating_div(24).clamp(1, 16);
    let tiny = image::imageops::resize(&crop, tiny_width, tiny_height, FilterType::Triangle);
    let mut redacted =
        image::imageops::resize(&tiny, rect.width, rect.height, FilterType::Triangle);
    for pixel in redacted.pixels_mut() {
        let channels = pixel.0;
        pixel.0 = [
            dim_redaction_channel(channels[0]),
            dim_redaction_channel(channels[1]),
            dim_redaction_channel(channels[2]),
            255,
        ];
    }
    image::imageops::replace(image, &redacted, i64::from(rect.left), i64::from(rect.top));
}

#[cfg(feature = "ocr")]
fn dim_redaction_channel(value: u8) -> u8 {
    ((u16::from(value) * 65 / 100) + 16).min(255) as u8
}

#[cfg(feature = "ocr")]
fn redacted_image_dimensions((width, height): (u32, u32), max_edge: u32) -> (u32, u32) {
    let width = width.max(1);
    let height = height.max(1);
    let max_edge = max_edge.clamp(128, 2_048);
    let (mut out_width, mut out_height) = if width <= max_edge && height <= max_edge {
        (width, height)
    } else if width >= height {
        let scaled_height = (u64::from(height) * u64::from(max_edge) / u64::from(width)).max(1);
        (max_edge, scaled_height as u32)
    } else {
        let scaled_width = (u64::from(width) * u64::from(max_edge) / u64::from(height)).max(1);
        (scaled_width as u32, max_edge)
    };
    out_width = out_width.max(128);
    out_height = out_height.max(128);
    (out_width, out_height)
}

#[cfg(feature = "ocr")]
fn fill_rect(
    image: &mut image::RgbaImage,
    left: u32,
    top: u32,
    width: u32,
    height: u32,
    color: image::Rgba<u8>,
) {
    let image_width = image.width() as usize;
    let image_height = image.height() as usize;
    let left = left.min(image.width()) as usize;
    let top = top.min(image.height()) as usize;
    let right = left.saturating_add(width as usize).min(image_width);
    let bottom = top.saturating_add(height as usize).min(image_height);
    if right <= left || bottom <= top {
        return;
    }
    let row_stride = image_width.saturating_mul(4);
    let row_left = left.saturating_mul(4);
    let row_right = right.saturating_mul(4);
    let data = image.as_mut();
    for y in top..bottom {
        let row_start = y.saturating_mul(row_stride).saturating_add(row_left);
        let row_end = y.saturating_mul(row_stride).saturating_add(row_right);
        let Some(row) = data.get_mut(row_start..row_end) else {
            continue;
        };
        for pixel in row.chunks_exact_mut(4) {
            pixel.copy_from_slice(&color.0);
        }
    }
}

#[cfg(feature = "ocr")]
fn image_barcode_regions(bytes: &[u8], cfg: &ImageOcrConfig) -> Vec<ImageTextRegion> {
    use image::GenericImageView;

    if matches!(cfg.mode, ImageOcrMode::Off) {
        return Vec::new();
    }
    let Ok(mut image) = image::load_from_memory(bytes) else {
        return Vec::new();
    };
    let (width, height) = image.dimensions();
    let pixels = u64::from(width).saturating_mul(u64::from(height));
    if pixels > cfg.max_pixels {
        return Vec::new();
    }
    image = resize_for_barcode(image, cfg.max_edge);
    let luma = image.into_luma8();
    let (width, height) = luma.dimensions();
    let Ok(results) = rxing::helpers::detect_multiple_in_luma(luma.into_raw(), width, height)
    else {
        return Vec::new();
    };
    let mut regions = Vec::new();
    for result in results {
        let text = result.getText();
        if text.trim().is_empty()
            || regions
                .iter()
                .any(|seen: &ImageTextRegion| seen.text == text)
        {
            continue;
        }
        regions.push(ImageTextRegion {
            text: text.to_string(),
            rect: NormalizedImageRect::from_points(result.getPoints(), width, height),
        });
    }
    regions
}

#[cfg(feature = "ocr")]
fn resize_for_barcode(img: image::DynamicImage, max_edge: u32) -> image::DynamicImage {
    use image::GenericImageView;

    let (width, height) = img.dimensions();
    if max_edge == 0 || (width <= max_edge && height <= max_edge) {
        return img;
    }
    img.resize(max_edge, max_edge, image::imageops::FilterType::Triangle)
}

fn image_ocr_secret_engine() -> &'static pentect_core::Engine {
    static ENGINE: std::sync::OnceLock<pentect_core::Engine> = std::sync::OnceLock::new();
    ENGINE.get_or_init(|| pentect_core::Engine::with_profile(pentect_core::Profile::Strict))
}

fn object_marks_image(map: &serde_json::Map<String, Value>) -> bool {
    map.iter().any(|(key, value)| {
        let key = normalized_json_key(key);
        key_marks_image_value(&key, value) || string_image_field(&key, value)
    })
}

fn image_object_bytes(
    map: &serde_json::Map<String, Value>,
    cfg: &ImageOcrConfig,
    max_bytes: u64,
    deadline: std::time::Instant,
) -> Result<Option<Vec<u8>>, String> {
    for &key in IMAGE_OBJECT_BYTE_FIELDS {
        let Some(text) = map.get(key).and_then(Value::as_str) else {
            continue;
        };
        if let Some(bytes) = image_reference_bytes(text, cfg, max_bytes, deadline)? {
            return Ok(Some(bytes));
        }
    }
    Ok(None)
}

fn image_reference_bytes(
    text: &str,
    cfg: &ImageOcrConfig,
    max_bytes: u64,
    deadline: std::time::Instant,
) -> Result<Option<Vec<u8>>, String> {
    if let Some(bytes) = inline_image_bytes(text, max_bytes)? {
        return Ok(Some(bytes));
    }
    fetch_image_url_bytes(text, cfg, max_bytes, deadline)
}

fn inline_image_bytes(text: &str, max_bytes: u64) -> Result<Option<Vec<u8>>, String> {
    let text = text.trim();
    if let Some(payload) = text
        .strip_prefix("data:image/")
        .and_then(|rest| rest.split_once(','))
        .and_then(|(meta, payload)| meta.contains(";base64").then_some(payload))
    {
        return decode_base64_limited(payload, max_bytes).map(Some);
    }
    if looks_like_base64_image(text) {
        return decode_base64_limited(text, max_bytes).map(Some);
    }
    Ok(None)
}

fn looks_like_base64_image(text: &str) -> bool {
    if text.len() < 64 {
        return false;
    }
    let compact = compact_base64(text);
    if compact.len() < 64 {
        return false;
    }
    decode_base64_prefix(&compact).is_some_and(|prefix| image_signature(&prefix).is_some())
}

fn decode_base64_limited(text: &str, max_bytes: u64) -> Result<Vec<u8>, String> {
    let compact = compact_base64(text);
    if base64_decoded_len_upper_bound(compact.len()) > max_bytes {
        return Err(format!("image is larger than {max_bytes} bytes"));
    }
    let bytes = data_encoding::BASE64
        .decode(compact.as_bytes())
        .map_err(|e| format!("image base64 is invalid: {e}"))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!("image is larger than {max_bytes} bytes"));
    }
    Ok(bytes)
}

fn base64_decoded_len_upper_bound(len: usize) -> u64 {
    let Ok(len) = u64::try_from(len) else {
        return u64::MAX;
    };
    len.div_ceil(4).saturating_mul(3)
}

fn decode_base64_prefix(text: &str) -> Option<Vec<u8>> {
    let len = text.len().min(256);
    let len = len - (len % 4);
    if len == 0 {
        return None;
    }
    data_encoding::BASE64.decode(&text.as_bytes()[..len]).ok()
}

fn compact_base64(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

fn looks_like_image_reference(text: &str) -> bool {
    let value = text.trim().to_ascii_lowercase();
    value.starts_with("data:image/")
        || image_extension_path(&value)
        || looks_like_remote_image_url(&value)
}

fn looks_like_remote_image_url(value: &str) -> bool {
    if !(value.starts_with("http://") || value.starts_with("https://")) {
        return false;
    }
    let path = value.split(['?', '#']).next().unwrap_or(value);
    image_extension_path(path)
}

fn image_extension_path(path: &str) -> bool {
    path.ends_with(".png")
        || path.ends_with(".jpg")
        || path.ends_with(".jpeg")
        || path.ends_with(".webp")
        || path.ends_with(".gif")
        || path.ends_with(".bmp")
}

fn key_marks_image_value(key: &str, value: &Value) -> bool {
    matches!(
        key,
        "image"
            | "images"
            | "imageurl"
            | "imageurls"
            | "screenshot"
            | "screenshots"
            | "thumbnail"
            | "qrcode"
    ) && !empty_json_value(value)
        && !matches!(value, Value::Array(_) | Value::Object(_))
}

fn string_image_field(key: &str, value: &Value) -> bool {
    let Some(text) = value.as_str() else {
        return false;
    };
    match key {
        "type" | "kind" => matches!(
            normalized_json_key(text).as_str(),
            "image" | "imageurl" | "screenshot" | "qrcode"
        ),
        "mimetype" | "mediatype" | "contenttype" => {
            text.trim().to_ascii_lowercase().starts_with("image/")
        }
        "url" | "uri" | "src" | "href" | "dataurl" => looks_like_image_reference(text),
        _ => false,
    }
}

fn normalized_json_key(key: &str) -> String {
    key.chars()
        .filter(|c| *c != '_' && *c != '-' && !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

fn empty_json_value(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(text) => text.trim().is_empty(),
        Value::Array(items) => items.is_empty(),
        Value::Object(map) => map.is_empty(),
        Value::Bool(false) => true,
        Value::Bool(true) | Value::Number(_) => false,
    }
}

fn empty_image_object(map: &serde_json::Map<String, Value>) -> bool {
    map.values().all(empty_json_value)
}

fn image_signature(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("png")
    } else if bytes.starts_with(b"\xff\xd8\xff") {
        Some("jpeg")
    } else if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
        Some("webp")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("gif")
    } else if bytes.starts_with(b"BM") {
        Some("bmp")
    } else {
        None
    }
}

#[cfg(feature = "ocr")]
fn fetch_image_url_bytes(
    text: &str,
    cfg: &ImageOcrConfig,
    max_bytes: u64,
    deadline: std::time::Instant,
) -> Result<Option<Vec<u8>>, String> {
    let url = text.trim();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Ok(None);
    }
    let mut url = reqwest::Url::parse(url).map_err(|e| format!("image URL is invalid: {e}"))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Ok(None);
    }

    for _ in 0..=IMAGE_URL_MAX_REDIRECTS {
        let response = send_image_url_request(&url, cfg, deadline)?;
        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| "image URL redirect has no location".to_string())?;
            url = url
                .join(location)
                .map_err(|e| format!("image URL redirect is invalid: {e}"))?;
            if url.scheme() != "http" && url.scheme() != "https" {
                return Err("image URL redirected to a non-HTTP URL".to_string());
            }
            continue;
        }
        return read_image_url_response(response, max_bytes).map(Some);
    }
    Err(format!(
        "image URL redirected more than {IMAGE_URL_MAX_REDIRECTS} times"
    ))
}

#[cfg(feature = "ocr")]
fn send_image_url_request(
    url: &reqwest::Url,
    cfg: &ImageOcrConfig,
    deadline: std::time::Instant,
) -> Result<reqwest::blocking::Response, String> {
    let host = url
        .host_str()
        .ok_or_else(|| "image URL has no host".to_string())?;
    let addrs = resolve_remote_image_url_target(url)?;
    let timeout = remaining_fetch_timeout(cfg, deadline)?;
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(host, &addrs)
        .build()
        .map_err(|e| format!("could not initialize image fetcher: {e}"))?;
    client
        .get(url.clone())
        .send()
        .map_err(|e| format!("could not fetch image URL: {e}"))
}

#[cfg(feature = "ocr")]
fn read_image_url_response(
    response: reqwest::blocking::Response,
    max_bytes: u64,
) -> Result<Vec<u8>, String> {
    use std::io::Read;

    if !response.status().is_success() {
        return Err(format!("image URL returned {}", response.status()));
    }
    if let Some(content_type) = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    {
        let content_type = content_type.to_ascii_lowercase();
        if !content_type.starts_with("image/") {
            return Err(format!("image URL content type is {content_type}"));
        }
    }
    if response.content_length().is_some_and(|len| len > max_bytes) {
        return Err(format!("image URL is larger than {max_bytes} bytes"));
    }

    let mut bytes = Vec::new();
    let mut limited = response.take(max_bytes + 1);
    limited
        .read_to_end(&mut bytes)
        .map_err(|e| format!("could not read image URL: {e}"))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!("image URL is larger than {max_bytes} bytes"));
    }
    if image_signature(&bytes).is_none() {
        return Err("image URL did not return a supported image".to_string());
    }
    Ok(bytes)
}

#[cfg(feature = "ocr")]
fn remaining_fetch_timeout(
    cfg: &ImageOcrConfig,
    deadline: std::time::Instant,
) -> Result<std::time::Duration, String> {
    let remaining = deadline
        .checked_duration_since(std::time::Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| "image scan time limit reached".to_string())?;
    Ok(remaining.min(std::time::Duration::from_secs(cfg.fetch_seconds)))
}

#[cfg(feature = "ocr")]
fn resolve_remote_image_url_target(url: &reqwest::Url) -> Result<Vec<SocketAddr>, String> {
    use std::net::ToSocketAddrs;

    let host = url
        .host_str()
        .ok_or_else(|| "image URL has no host".to_string())?;
    let host_lc = host.to_ascii_lowercase();
    if host_lc == "localhost" || host_lc.ends_with(".localhost") {
        local_image_url_result()?;
    }
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "image URL has no port".to_string())?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        validate_remote_image_ip(ip)?;
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("could not resolve image URL host: {e}"))?
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err("image URL host did not resolve".to_string());
    }
    for addr in &addrs {
        validate_remote_image_ip(addr.ip())?;
    }
    Ok(addrs)
}

#[cfg(feature = "ocr")]
fn validate_remote_image_ip(ip: IpAddr) -> Result<(), String> {
    if remote_image_ip_is_private(ip) {
        return local_image_url_result();
    }
    Ok(())
}

#[cfg(all(feature = "ocr", test))]
fn local_image_url_result() -> Result<(), String> {
    Ok(())
}

#[cfg(all(feature = "ocr", not(test)))]
fn local_image_url_result() -> Result<(), String> {
    Err("image URL points to a local or private network address".to_string())
}

#[cfg(feature = "ocr")]
fn remote_image_ip_is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_multicast()
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
        }
    }
}

#[cfg(not(feature = "ocr"))]
fn fetch_image_url_bytes(
    _text: &str,
    _cfg: &ImageOcrConfig,
    _max_bytes: u64,
    _deadline: std::time::Instant,
) -> Result<Option<Vec<u8>>, String> {
    Ok(None)
}

#[cfg(all(feature = "ocr", target_os = "linux"))]
pub fn ocr_status() -> &'static str {
    "bundled"
}

#[cfg(all(feature = "ocr", target_os = "windows"))]
pub fn ocr_status() -> &'static str {
    "windows"
}

#[cfg(all(feature = "ocr", target_os = "macos"))]
pub fn ocr_status() -> &'static str {
    "macos"
}

#[cfg(all(
    feature = "ocr",
    not(any(target_os = "linux", target_os = "windows", target_os = "macos"))
))]
pub fn ocr_status() -> &'static str {
    "unsupported"
}

#[cfg(not(feature = "ocr"))]
pub fn ocr_status() -> &'static str {
    "disabled"
}

#[cfg(all(feature = "ocr", target_os = "windows"))]
pub fn ocr_image_bytes(bytes: &[u8]) -> Result<String, String> {
    let cfg = image_ocr_config()?;
    ocr_image_bytes_with_config(bytes, &cfg)
}

#[cfg(all(feature = "ocr", target_os = "windows"))]
fn ocr_image_bytes_with_config(bytes: &[u8], cfg: &ImageOcrConfig) -> Result<String, String> {
    let regions = ocr_image_regions_with_config(bytes, cfg)?;
    Ok(image_regions_text(&regions))
}

#[cfg(all(feature = "ocr", target_os = "windows"))]
fn ocr_image_regions_with_config(
    bytes: &[u8],
    cfg: &ImageOcrConfig,
) -> Result<Vec<ImageTextRegion>, String> {
    use windows::Graphics::Imaging::{
        BitmapAlphaMode, BitmapDecoder, BitmapInterpolationMode, BitmapPixelFormat,
        BitmapTransform, ColorManagementMode, ExifOrientationMode,
    };
    use windows::Media::Ocr::OcrEngine;
    use windows::Storage::Streams::{DataWriter, InMemoryRandomAccessStream};

    if matches!(cfg.mode, ImageOcrMode::Off) {
        return Err("image OCR disabled".to_string());
    }
    if bytes.len() as u64 > cfg.max_image_bytes {
        return Err(format!(
            "image is larger than {} bytes",
            cfg.max_image_bytes
        ));
    }

    let stream = InMemoryRandomAccessStream::new()
        .map_err(|e| format!("could not initialize image stream: {e}"))?;
    let output = stream
        .GetOutputStreamAt(0)
        .map_err(|e| format!("could not open image stream: {e}"))?;
    let writer = DataWriter::CreateDataWriter(&output)
        .map_err(|e| format!("could not initialize image writer: {e}"))?;
    writer
        .WriteBytes(bytes)
        .map_err(|e| format!("could not write image bytes: {e}"))?;
    writer
        .StoreAsync()
        .map_err(|e| format!("could not store image bytes: {e}"))?
        .join()
        .map_err(|e| format!("could not store image bytes: {e}"))?;
    writer
        .FlushAsync()
        .map_err(|e| format!("could not flush image bytes: {e}"))?
        .join()
        .map_err(|e| format!("could not flush image bytes: {e}"))?;
    stream
        .Seek(0)
        .map_err(|e| format!("could not rewind image stream: {e}"))?;

    let decoder = BitmapDecoder::CreateAsync(&stream)
        .map_err(|e| format!("could not decode image: {e}"))?
        .join()
        .map_err(|e| format!("could not decode image: {e}"))?;
    let width = decoder
        .PixelWidth()
        .map_err(|e| format!("could not read image width: {e}"))?;
    let height = decoder
        .PixelHeight()
        .map_err(|e| format!("could not read image height: {e}"))?;
    let pixels = u64::from(width).saturating_mul(u64::from(height));
    if pixels > cfg.max_pixels {
        return Err(format!(
            "image has {pixels} pixels; limit is {}",
            cfg.max_pixels
        ));
    }

    let max_dimension = OcrEngine::MaxImageDimension()
        .map_err(|e| format!("could not read OCR image limit: {e}"))?
        .min(cfg.max_edge);
    let (scaled_width, scaled_height) = scaled_dimensions(width, height, max_dimension);
    let transform =
        BitmapTransform::new().map_err(|e| format!("could not initialize image transform: {e}"))?;
    transform
        .SetScaledWidth(scaled_width)
        .map_err(|e| format!("could not set image width: {e}"))?;
    transform
        .SetScaledHeight(scaled_height)
        .map_err(|e| format!("could not set image height: {e}"))?;
    transform
        .SetInterpolationMode(BitmapInterpolationMode::Fant)
        .map_err(|e| format!("could not set image interpolation: {e}"))?;

    let bitmap = decoder
        .GetSoftwareBitmapTransformedAsync(
            BitmapPixelFormat::Bgra8,
            BitmapAlphaMode::Premultiplied,
            &transform,
            ExifOrientationMode::RespectExifOrientation,
            ColorManagementMode::ColorManageToSRgb,
        )
        .map_err(|e| format!("could not prepare image bitmap: {e}"))?
        .join()
        .map_err(|e| format!("could not prepare image bitmap: {e}"))?;
    let engine = OcrEngine::TryCreateFromUserProfileLanguages()
        .map_err(|e| format!("could not initialize Windows OCR: {e}"))?;
    let result = engine
        .RecognizeAsync(&bitmap)
        .map_err(|e| format!("could not start Windows OCR: {e}"))?
        .join()
        .map_err(|e| format!("could not OCR image: {e}"))?;
    let lines = result
        .Lines()
        .map_err(|e| format!("could not read OCR lines: {e}"))?;
    let mut regions = Vec::new();
    for index in 0..lines
        .Size()
        .map_err(|e| format!("could not count OCR lines: {e}"))?
    {
        let line = lines
            .GetAt(index)
            .map_err(|e| format!("could not read OCR line: {e}"))?;
        let text = line
            .Text()
            .map(|text| text.to_string_lossy())
            .map_err(|e| format!("could not read OCR line text: {e}"))?;
        if text.trim().is_empty() {
            continue;
        }
        let words = line
            .Words()
            .map_err(|e| format!("could not read OCR words: {e}"))?;
        let mut left = f32::MAX;
        let mut top = f32::MAX;
        let mut right = f32::MIN;
        let mut bottom = f32::MIN;
        for word_index in 0..words
            .Size()
            .map_err(|e| format!("could not count OCR words: {e}"))?
        {
            let word = words
                .GetAt(word_index)
                .map_err(|e| format!("could not read OCR word: {e}"))?;
            let rect = word
                .BoundingRect()
                .map_err(|e| format!("could not read OCR word bounds: {e}"))?;
            left = left.min(rect.X);
            top = top.min(rect.Y);
            right = right.max(rect.X + rect.Width);
            bottom = bottom.max(rect.Y + rect.Height);
        }
        let rect = if right > left && bottom > top {
            NormalizedImageRect::from_pixels(
                left,
                top,
                right - left,
                bottom - top,
                scaled_width,
                scaled_height,
            )
        } else {
            None
        };
        regions.push(ImageTextRegion { text, rect });
    }
    Ok(regions)
}

#[cfg(all(feature = "ocr", target_os = "windows"))]
fn scaled_dimensions(width: u32, height: u32, max_edge: u32) -> (u32, u32) {
    if max_edge == 0 || (width <= max_edge && height <= max_edge) {
        return (width.max(1), height.max(1));
    }
    if width >= height {
        let scaled_height = (u64::from(height) * u64::from(max_edge) / u64::from(width)).max(1);
        (max_edge, scaled_height as u32)
    } else {
        let scaled_width = (u64::from(width) * u64::from(max_edge) / u64::from(height)).max(1);
        (scaled_width as u32, max_edge)
    }
}

#[cfg(all(feature = "ocr", target_os = "macos"))]
pub fn ocr_image_bytes(bytes: &[u8]) -> Result<String, String> {
    let cfg = image_ocr_config()?;
    ocr_image_bytes_with_config(bytes, &cfg)
}

#[cfg(all(feature = "ocr", target_os = "macos"))]
fn ocr_image_bytes_with_config(bytes: &[u8], cfg: &ImageOcrConfig) -> Result<String, String> {
    let regions = ocr_image_regions_with_config(bytes, cfg)?;
    Ok(image_regions_text(&regions))
}

#[cfg(all(feature = "ocr", target_os = "macos"))]
fn ocr_image_regions_with_config(
    bytes: &[u8],
    cfg: &ImageOcrConfig,
) -> Result<Vec<ImageTextRegion>, String> {
    use objc2::{runtime::AnyObject, AnyThread};
    use objc2_foundation::{NSArray, NSData, NSDictionary};
    use objc2_vision::{
        VNImageOption, VNImageRequestHandler, VNRecognizeTextRequest, VNRequestTextRecognitionLevel,
    };

    if matches!(cfg.mode, ImageOcrMode::Off) {
        return Err("image OCR disabled".to_string());
    }
    if bytes.len() as u64 > cfg.max_image_bytes {
        return Err(format!(
            "image is larger than {} bytes",
            cfg.max_image_bytes
        ));
    }

    let ocr_bytes = prepare_macos_ocr_bytes(bytes, cfg)?;
    let data = NSData::with_bytes(ocr_bytes.as_ref());
    let options = NSDictionary::<VNImageOption, AnyObject>::from_slices::<VNImageOption>(&[], &[]);
    let request = VNRecognizeTextRequest::new();
    request.setRecognitionLevel(VNRequestTextRecognitionLevel::Fast);
    request.setAutomaticallyDetectsLanguage(true);
    request.setUsesLanguageCorrection(false);

    let request_for_handler = request.clone().into_super().into_super();
    let requests = NSArray::from_retained_slice(&[request_for_handler]);
    let handler = VNImageRequestHandler::initWithData_options(
        VNImageRequestHandler::alloc(),
        &data,
        &options,
    );
    handler
        .performRequests_error(&requests)
        .map_err(|e| format!("could not OCR image with macOS Vision: {e}"))?;

    let Some(observations) = request.results() else {
        return Ok(Vec::new());
    };
    let mut regions = Vec::new();
    for index in 0..observations.len() {
        let observation = observations.objectAtIndex(index);
        let candidates = observation.topCandidates(1);
        if candidates.is_empty() {
            continue;
        }
        let candidate = candidates.objectAtIndex(0);
        let text = candidate.string().to_string();
        if text.trim().is_empty() {
            continue;
        }
        let rect =
            NormalizedImageRect::from_macos_vision_rect(unsafe { observation.boundingBox() });
        regions.push(ImageTextRegion { text, rect });
    }
    Ok(regions)
}

#[cfg(all(feature = "ocr", target_os = "macos"))]
fn prepare_macos_ocr_bytes<'a>(
    bytes: &'a [u8],
    cfg: &ImageOcrConfig,
) -> Result<std::borrow::Cow<'a, [u8]>, String> {
    use image::{GenericImageView, ImageFormat, ImageReader};
    use std::{borrow::Cow, io::Cursor};

    let reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|e| format!("could not inspect image: {e}"))?;
    let (width, height) = reader
        .into_dimensions()
        .map_err(|e| format!("could not read image dimensions: {e}"))?;
    let pixels = u64::from(width).saturating_mul(u64::from(height));
    if pixels > cfg.max_pixels {
        return Err(format!(
            "image has {pixels} pixels; limit is {}",
            cfg.max_pixels
        ));
    }
    if cfg.max_edge == 0 || (width <= cfg.max_edge && height <= cfg.max_edge) {
        return Ok(Cow::Borrowed(bytes));
    }

    let img = image::load_from_memory(bytes).map_err(|e| format!("could not decode image: {e}"))?;
    let resized = img.resize(
        cfg.max_edge,
        cfg.max_edge,
        image::imageops::FilterType::Triangle,
    );
    let (resized_width, resized_height) = resized.dimensions();
    let resized_pixels = u64::from(resized_width).saturating_mul(u64::from(resized_height));
    if resized_pixels > cfg.max_pixels {
        return Err(format!(
            "image has {resized_pixels} pixels after resize; limit is {}",
            cfg.max_pixels
        ));
    }

    let mut out = Vec::new();
    resized
        .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
        .map_err(|e| format!("could not prepare image for macOS OCR: {e}"))?;
    Ok(Cow::Owned(out))
}

#[cfg(all(feature = "ocr", target_os = "linux"))]
pub fn ocr_image_bytes(bytes: &[u8]) -> Result<String, String> {
    let cfg = image_ocr_config()?;
    ocr_image_bytes_with_config(bytes, &cfg)
}

#[cfg(all(feature = "ocr", target_os = "linux"))]
fn ocr_image_bytes_with_config(bytes: &[u8], cfg: &ImageOcrConfig) -> Result<String, String> {
    let regions = ocr_image_regions_with_config(bytes, cfg)?;
    Ok(image_regions_text(&regions))
}

#[cfg(all(feature = "ocr", target_os = "linux"))]
fn ocr_image_regions_with_config(
    bytes: &[u8],
    cfg: &ImageOcrConfig,
) -> Result<Vec<ImageTextRegion>, String> {
    use image::GenericImageView;
    use ocrs::{ImageSource, OcrEngine, OcrEngineParams, TextItem};
    use rten::Model;
    use std::sync::OnceLock;

    static ENGINE: OnceLock<Result<OcrEngine, String>> = OnceLock::new();

    if matches!(cfg.mode, ImageOcrMode::Off) {
        return Err("image OCR disabled".to_string());
    }

    let img = image::load_from_memory(bytes).map_err(|e| format!("could not decode image: {e}"))?;
    let (width, height) = img.dimensions();
    let pixels = u64::from(width).saturating_mul(u64::from(height));
    if pixels > cfg.max_pixels {
        return Err(format!(
            "image has {pixels} pixels; limit is {}",
            cfg.max_pixels
        ));
    }

    let img = resize_for_ocr(img, cfg.max_edge);
    let (ocr_width, ocr_height) = img.dimensions();
    let img = img.into_rgb8();
    let img_source = ImageSource::from_bytes(img.as_raw(), img.dimensions())
        .map_err(|e| format!("could not prepare image: {e}"))?;
    let engine = ENGINE
        .get_or_init(|| {
            let detection_model =
                Model::load_static_slice(include_bytes!("../assets/ocr/text-detection.rten"))
                    .map_err(|e| format!("could not load OCR detection model: {e}"))?;
            let recognition_model =
                Model::load_static_slice(include_bytes!("../assets/ocr/text-recognition.rten"))
                    .map_err(|e| format!("could not load OCR recognition model: {e}"))?;
            OcrEngine::new(OcrEngineParams {
                detection_model: Some(detection_model),
                recognition_model: Some(recognition_model),
                ..Default::default()
            })
            .map_err(|e| format!("could not initialize OCR: {e}"))
        })
        .as_ref()
        .map_err(Clone::clone)?;
    let input = engine
        .prepare_input(img_source)
        .map_err(|e| format!("could not preprocess image: {e}"))?;
    let words = engine
        .detect_words(&input)
        .map_err(|e| format!("could not detect OCR words: {e}"))?;
    let lines = engine.find_text_lines(&input, &words);
    let recognized = engine
        .recognize_text(&input, &lines)
        .map_err(|e| format!("could not OCR image: {e}"))?;
    let mut regions = Vec::new();
    for line in recognized.into_iter().flatten() {
        let text = line.to_string();
        if text.trim().is_empty() {
            continue;
        }
        let bounds = line.bounding_rect();
        let rect = NormalizedImageRect::from_pixels(
            bounds.left() as f32,
            bounds.top() as f32,
            bounds.width() as f32,
            bounds.height() as f32,
            ocr_width,
            ocr_height,
        );
        regions.push(ImageTextRegion { text, rect });
    }
    Ok(regions)
}

#[cfg(all(feature = "ocr", target_os = "linux"))]
fn resize_for_ocr(img: image::DynamicImage, max_edge: u32) -> image::DynamicImage {
    use image::GenericImageView;

    let (width, height) = img.dimensions();
    if width <= max_edge && height <= max_edge {
        return img;
    }
    img.resize(max_edge, max_edge, image::imageops::FilterType::Triangle)
}

#[cfg(all(
    feature = "ocr",
    not(any(target_os = "linux", target_os = "windows", target_os = "macos"))
))]
pub fn ocr_image_bytes(_bytes: &[u8]) -> Result<String, String> {
    Err("image OCR is not supported on this platform".to_string())
}

#[cfg(all(
    feature = "ocr",
    not(any(target_os = "linux", target_os = "windows", target_os = "macos"))
))]
fn ocr_image_bytes_with_config(_bytes: &[u8], _cfg: &ImageOcrConfig) -> Result<String, String> {
    Err("image OCR is not supported on this platform".to_string())
}

#[cfg(all(
    feature = "ocr",
    not(any(target_os = "linux", target_os = "windows", target_os = "macos"))
))]
fn ocr_image_regions_with_config(
    _bytes: &[u8],
    _cfg: &ImageOcrConfig,
) -> Result<Vec<ImageTextRegion>, String> {
    Err("image OCR is not supported on this platform".to_string())
}

#[cfg(not(feature = "ocr"))]
pub fn ocr_image_bytes(_bytes: &[u8]) -> Result<String, String> {
    Err("image OCR requires a build with `--features ocr`".to_string())
}

#[cfg(not(feature = "ocr"))]
fn ocr_image_bytes_with_config(_bytes: &[u8], _cfg: &ImageOcrConfig) -> Result<String, String> {
    Err("image OCR requires a build with `--features ocr`".to_string())
}

#[cfg(not(feature = "ocr"))]
fn ocr_image_regions_with_config(
    _bytes: &[u8],
    _cfg: &ImageOcrConfig,
) -> Result<Vec<ImageTextRegion>, String> {
    Err("image OCR requires a build with `--features ocr`".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ImageOcrMode, ImageRedactionStyle, UnscannedImagePolicy};

    fn test_config() -> ImageOcrConfig {
        ImageOcrConfig {
            mode: ImageOcrMode::On,
            redaction: ImageRedactionStyle::Black,
            max_pixels: 64_000_000,
            max_edge: 2_048,
            max_images: 64,
            max_total_bytes: 512 * 1024 * 1024,
            max_seconds: 20,
            max_image_bytes: 64 * 1024 * 1024,
            fetch_seconds: 8,
            unscanned_images: UnscannedImagePolicy::Allow,
        }
    }

    #[cfg(feature = "ocr")]
    fn color_grid_png() -> Vec<u8> {
        use image::{ImageFormat, Rgba, RgbaImage};
        use std::io::Cursor;

        let mut img = RgbaImage::from_pixel(320, 180, Rgba([240, 240, 240, 255]));
        for y in 0..180 {
            for x in 0..320 {
                let color = match (x >= 160, y >= 90) {
                    (false, false) => Rgba([220, 80, 80, 255]),
                    (true, false) => Rgba([80, 170, 110, 255]),
                    (false, true) => Rgba([80, 120, 220, 255]),
                    (true, true) => Rgba([220, 190, 80, 255]),
                };
                img.put_pixel(x, y, color);
            }
        }
        let mut out = Vec::new();
        image::DynamicImage::ImageRgba8(img)
            .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .unwrap();
        out
    }

    #[cfg(feature = "ocr")]
    fn solid_jpeg_with_app1(app1: &[u8]) -> Vec<u8> {
        use image::{codecs::jpeg::JpegEncoder, Rgb, RgbImage};

        let img = RgbImage::from_pixel(48, 32, Rgb([220, 120, 40]));
        let mut jpeg = Vec::new();
        JpegEncoder::new_with_quality(&mut jpeg, 95)
            .encode_image(&img)
            .unwrap();
        let len = app1.len() + 2;
        assert!(len <= u16::MAX as usize);
        let mut out = Vec::with_capacity(jpeg.len() + len + 2);
        out.extend_from_slice(&jpeg[..2]);
        out.extend_from_slice(&[0xff, 0xe1, (len >> 8) as u8, len as u8]);
        out.extend_from_slice(app1);
        out.extend_from_slice(&jpeg[2..]);
        out
    }

    #[cfg(feature = "ocr")]
    fn exif_text_payload(text: &str) -> Vec<u8> {
        let mut payload = b"Exif\0\0II*\0\x08\0\0\0\0\0".to_vec();
        payload.extend_from_slice(text.as_bytes());
        payload
    }

    #[cfg(feature = "ocr")]
    fn exif_gps_payload() -> Vec<u8> {
        let mut payload = b"Exif\0\0II*\0\x08\0\0\0".to_vec();
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.extend_from_slice(&0x8825u16.to_le_bytes());
        payload.extend_from_slice(&4u16.to_le_bytes());
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&26u32.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload
    }

    #[cfg(feature = "ocr")]
    fn png_with_text_chunk(keyword: &str, value: &str) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(keyword.as_bytes());
        data.push(0);
        data.extend_from_slice(value.as_bytes());
        png_with_raw_chunk(*b"tEXt", &data)
    }

    #[cfg(feature = "ocr")]
    fn png_with_ztxt_chunk(keyword: &str, value: &str) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(keyword.as_bytes());
        data.push(0);
        data.push(0);
        data.extend_from_slice(&zlib_compress(value.as_bytes()));
        png_with_raw_chunk(*b"zTXt", &data)
    }

    #[cfg(feature = "ocr")]
    fn png_with_compressed_itxt_chunk(keyword: &str, value: &str) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(keyword.as_bytes());
        data.push(0);
        data.push(1);
        data.push(0);
        data.push(0);
        data.push(0);
        data.extend_from_slice(&zlib_compress(value.as_bytes()));
        png_with_raw_chunk(*b"iTXt", &data)
    }

    #[cfg(feature = "ocr")]
    fn zlib_compress(bytes: &[u8]) -> Vec<u8> {
        use flate2::{write::ZlibEncoder, Compression};
        use std::io::Write;

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    #[cfg(feature = "ocr")]
    fn png_with_raw_chunk(kind: [u8; 4], data: &[u8]) -> Vec<u8> {
        let mut png = color_grid_png();
        let iend = png
            .windows(8)
            .position(|window| window == b"\0\0\0\0IEND")
            .unwrap();
        let len = data.len() as u32;
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&len.to_be_bytes());
        chunk.extend_from_slice(&kind);
        chunk.extend_from_slice(data);
        let mut crc_input = Vec::with_capacity(4 + data.len());
        crc_input.extend_from_slice(&kind);
        crc_input.extend_from_slice(data);
        chunk.extend_from_slice(&crc32(&crc_input).to_be_bytes());
        png.splice(iend..iend, chunk);
        png
    }

    #[cfg(feature = "ocr")]
    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = 0xffff_ffffu32;
        for &byte in bytes {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                let mask = 0u32.wrapping_sub(crc & 1);
                crc = (crc >> 1) ^ (0xedb8_8320 & mask);
            }
        }
        !crc
    }

    #[cfg(feature = "ocr")]
    fn metadata_test_config() -> ImageOcrConfig {
        let mut cfg = test_config();
        cfg.max_pixels = 1;
        cfg
    }

    #[cfg(feature = "ocr")]
    fn decode_redacted_payload(payload: &RedactedImagePayload) -> image::RgbaImage {
        let bytes = data_encoding::BASE64
            .decode(payload.base64.as_bytes())
            .unwrap();
        image::load_from_memory(&bytes).unwrap().to_rgba8()
    }

    #[cfg(feature = "ocr")]
    fn test_finding(force_black: bool) -> ImageSecretFinding {
        ImageSecretFinding {
            labels: vec![labels::KEYED_SECRET.to_string()],
            rect: NormalizedImageRect::new(0.12, 0.16, 0.42, 0.46),
            force_black,
            pad_left: true,
            redact_pixels: true,
        }
    }

    #[test]
    fn fragmented_ocr_key_value_line_is_secret() {
        let text = concat!(
            "Kaggle API settings API token KAGGLE API TOKEN=KGAT ab ",
            "( def123456789 ② ab ( def123456 footer"
        );
        let labels = ocr_fragmented_secret_labels(text);
        assert!(
            labels.contains(&"KAGGLE_API_TOKEN".to_string()),
            "{labels:?}"
        );
    }

    #[test]
    fn fragmented_ocr_key_without_value_shape_is_not_secret() {
        for text in [
            "Kaggle API settings API token Create new token",
            "API token = disabled",
            "secret capability can be configured here",
        ] {
            assert!(ocr_fragmented_secret_labels(text).is_empty(), "{text}");
        }
    }

    #[cfg(feature = "ocr")]
    fn qr_png(payload: &str) -> Vec<u8> {
        use image::{GrayImage, ImageFormat, Luma};
        use rxing::{BarcodeFormat, Writer};
        use std::io::Cursor;

        let writer = rxing::qrcode::QRCodeWriter {};
        let matrix = writer
            .encode(payload, &BarcodeFormat::QR_CODE, 192, 192)
            .unwrap();
        let mut img = GrayImage::from_pixel(matrix.getWidth(), matrix.getHeight(), Luma([255]));
        for y in 0..matrix.getHeight() {
            for x in 0..matrix.getWidth() {
                if matrix.get(x, y) {
                    img.put_pixel(x, y, Luma([0]));
                }
            }
        }
        let mut out = Vec::new();
        image::DynamicImage::ImageLuma8(img)
            .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .unwrap();
        out
    }

    #[cfg(feature = "ocr")]
    #[test]
    fn jpeg_exif_secret_metadata_is_detected_without_pixel_redaction() {
        let app1 = exif_text_payload("OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX");
        let jpeg = solid_jpeg_with_app1(&app1);
        let findings = image_secret_findings(&jpeg, &[7; 32], &metadata_test_config()).unwrap();
        let exif_finding = findings
            .iter()
            .find(|finding| finding.labels.iter().any(|label| label == "OPENAI_API_KEY"))
            .unwrap_or_else(|| panic!("missing EXIF secret finding: {findings:?}"));
        assert!(!exif_finding.redact_pixels);
    }

    #[cfg(feature = "ocr")]
    #[test]
    fn jpeg_exif_gps_metadata_is_detected_without_pixel_redaction() {
        let jpeg = solid_jpeg_with_app1(&exif_gps_payload());
        let findings = image_secret_findings(&jpeg, &[7; 32], &metadata_test_config()).unwrap();
        let gps_finding = findings
            .iter()
            .find(|finding| {
                finding
                    .labels
                    .iter()
                    .any(|label| label == labels::IMAGE_GPS_METADATA)
            })
            .unwrap_or_else(|| panic!("missing EXIF GPS finding: {findings:?}"));
        assert!(!gps_finding.redact_pixels);
    }

    #[cfg(feature = "ocr")]
    #[test]
    fn png_text_metadata_secret_is_detected_without_pixel_redaction() {
        let png = png_with_text_chunk("Description", "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX");
        let findings = image_secret_findings(&png, &[7; 32], &metadata_test_config()).unwrap();
        let text_finding = findings
            .iter()
            .find(|finding| finding.labels.iter().any(|label| label == "OPENAI_API_KEY"))
            .unwrap_or_else(|| panic!("missing PNG text metadata finding: {findings:?}"));
        assert!(!text_finding.redact_pixels);
    }

    #[cfg(feature = "ocr")]
    #[test]
    fn compressed_png_text_metadata_secret_is_detected_without_pixel_redaction() {
        for png in [
            png_with_ztxt_chunk("Description", "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX"),
            png_with_compressed_itxt_chunk(
                "Description",
                "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX",
            ),
        ] {
            let findings = image_secret_findings(&png, &[7; 32], &metadata_test_config()).unwrap();
            let text_finding = findings
                .iter()
                .find(|finding| finding.labels.iter().any(|label| label == "OPENAI_API_KEY"))
                .unwrap_or_else(|| panic!("missing compressed PNG metadata finding: {findings:?}"));
            assert!(!text_finding.redact_pixels);
        }
    }

    #[cfg(feature = "ocr")]
    #[test]
    fn metadata_only_redaction_strips_metadata_without_reencoding() {
        let app1 = exif_text_payload("OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX");
        let jpeg = solid_jpeg_with_app1(&app1);
        let findings = vec![ImageSecretFinding {
            labels: vec!["OPENAI_API_KEY".to_string()],
            rect: None,
            force_black: false,
            pad_left: false,
            redact_pixels: false,
        }];
        let payload = redacted_image_payload(&jpeg, 1, &metadata_test_config(), &findings).unwrap();
        let redacted_bytes = data_encoding::BASE64
            .decode(payload.base64.as_bytes())
            .unwrap();
        assert_eq!(payload.mime_type, "image/jpeg");
        assert!(payload.data_url.starts_with("data:image/jpeg;base64,"));
        assert_eq!(image_signature(&redacted_bytes), Some("jpeg"));
        assert!(image_metadata_regions(&redacted_bytes).is_empty());
        assert!(jpeg_app1_segments(&redacted_bytes).is_empty());
    }

    #[cfg(feature = "ocr")]
    #[test]
    fn black_redaction_only_covers_secret_rect() {
        let mut cfg = test_config();
        cfg.redaction = ImageRedactionStyle::Black;
        let payload =
            redacted_image_payload(&color_grid_png(), 1, &cfg, &[test_finding(false)]).unwrap();
        let image = decode_redacted_payload(&payload);
        let inside = image.get_pixel(80, 50).0;
        let outside = image.get_pixel(250, 140).0;
        assert!(inside[0] < 32 && inside[1] < 32 && inside[2] < 32);
        assert_eq!([outside[0], outside[1], outside[2]], [220, 190, 80]);
    }

    #[cfg(feature = "ocr")]
    #[test]
    fn blur_redaction_only_covers_secret_rect() {
        let mut cfg = test_config();
        cfg.redaction = ImageRedactionStyle::Blur;
        let payload =
            redacted_image_payload(&color_grid_png(), 1, &cfg, &[test_finding(false)]).unwrap();
        let image = decode_redacted_payload(&payload);
        let inside = image.get_pixel(80, 50).0;
        let outside = image.get_pixel(250, 140).0;
        assert_ne!([inside[0], inside[1], inside[2]], [220, 80, 80]);
        assert_eq!([outside[0], outside[1], outside[2]], [220, 190, 80]);
    }

    #[cfg(feature = "ocr")]
    #[test]
    fn forced_black_redaction_overrides_blur() {
        let mut cfg = test_config();
        cfg.redaction = ImageRedactionStyle::Blur;
        let payload =
            redacted_image_payload(&color_grid_png(), 1, &cfg, &[test_finding(true)]).unwrap();
        let image = decode_redacted_payload(&payload);
        let inside = image.get_pixel(80, 50).0;
        let outside = image.get_pixel(250, 140).0;
        assert!(inside[0] < 32 && inside[1] < 32 && inside[2] < 32);
        assert_eq!([outside[0], outside[1], outside[2]], [220, 190, 80]);
    }

    #[cfg(feature = "ocr")]
    #[test]
    fn ocr_secret_rect_uses_value_span_when_available() {
        let text = "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX";
        let value_start = text.find("sk-").unwrap();
        let hits = image_text_secret_hits(text, &[7; 32]);
        let hit = hits
            .iter()
            .find(|hit| hit.range.is_some_and(|range| range.start >= value_start))
            .unwrap_or_else(|| panic!("missing value hit in {hits:?}"));
        let region = ImageTextRegion {
            text: text.to_string(),
            rect: NormalizedImageRect::new(0.0, 0.20, 1.0, 0.30),
        };
        let redaction = rect_for_text_secret_hit(&region, hit);
        let rect = redaction.rect.unwrap();
        assert!(!redaction.pad_left);
        assert!(rect.left > 0.25, "{rect:?}");
        assert!(rect.left < 0.50, "{rect:?}");
        assert_eq!(rect.top, 0.20);
        assert_eq!(rect.bottom, 0.30);
    }

    #[cfg(feature = "ocr")]
    #[test]
    fn ocr_secret_rect_uses_value_side_without_span() {
        let text = "KAGGLE_API_TOKEN=KGAT_abcdefghijklmnopqrstuvwxyz123456";
        let region = ImageTextRegion {
            text: text.to_string(),
            rect: NormalizedImageRect::new(0.0, 0.20, 1.0, 0.30),
        };
        let hit = ImageTextSecretHit {
            label: "KAGGLE_API_TOKEN".to_string(),
            range: None,
        };
        let redaction = rect_for_text_secret_hit(&region, &hit);
        let rect = redaction.rect.unwrap();
        assert!(!redaction.pad_left);
        assert!(rect.left > 0.25, "{rect:?}");
        assert!(rect.left < 0.50, "{rect:?}");
        assert_eq!(rect.top, 0.20);
        assert_eq!(rect.bottom, 0.30);
    }

    #[cfg(feature = "ocr")]
    #[test]
    fn joined_ocr_regions_detect_split_seed_phrase() {
        let regions = vec![
            ImageTextRegion {
                text: "seed phrase: abandon abandon abandon abandon abandon abandon".to_string(),
                rect: NormalizedImageRect::new(0.10, 0.20, 0.80, 0.30),
            },
            ImageTextRegion {
                text: "abandon abandon abandon abandon abandon about".to_string(),
                rect: NormalizedImageRect::new(0.10, 0.32, 0.76, 0.42),
            },
        ];
        assert!(regions
            .iter()
            .all(|region| image_text_secret_labels(&region.text, &[7; 32]).is_empty()));
        let labels = image_text_secret_labels(&image_regions_text(&regions), &[7; 32]);
        assert!(labels.contains(&labels::BIP39_MNEMONIC.to_string()));
        let rect = union_region_rects(&regions).unwrap();
        assert_eq!(
            rect,
            NormalizedImageRect::new(0.10, 0.20, 0.80, 0.42).unwrap()
        );
    }

    #[test]
    fn data_url_image_payload_is_decoded() {
        let png = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII=";
        let bytes = inline_image_bytes(png, test_config().max_image_bytes)
            .unwrap()
            .unwrap();
        assert_eq!(image_signature(&bytes), Some("png"));
    }

    #[test]
    fn object_image_payload_is_readable_when_inline() {
        let value = serde_json::json!({
            "type": "image",
            "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII="
        });
        let map = value.as_object().unwrap();
        assert!(object_marks_image(map));
        assert!(image_object_bytes(
            map,
            &test_config(),
            test_config().max_image_bytes,
            std::time::Instant::now() + std::time::Duration::from_secs(20)
        )
        .unwrap()
        .is_some());
    }

    #[test]
    fn nested_image_url_object_is_inspected_by_inner_url() {
        let value = serde_json::json!({
            "image_url": {
                "url": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII="
            }
        });
        assert!(contains_image_result(&value));
        let outer = value.as_object().unwrap();
        assert!(!object_marks_image(outer));
        let inner = value["image_url"].as_object().unwrap();
        assert!(object_marks_image(inner));
        assert!(image_object_bytes(
            inner,
            &test_config(),
            test_config().max_image_bytes,
            std::time::Instant::now() + std::time::Duration::from_secs(20)
        )
        .unwrap()
        .is_some());
    }

    #[test]
    fn bare_base64_image_is_inspected() {
        let value = serde_json::json!(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII="
        );
        let inspection = inspect_tool_images_for_secrets(&value, &[7; 32], &test_config()).unwrap();
        assert_eq!(inspection.scanned_images, 1);
        assert_eq!(inspection.unscanned_images, 0);
    }

    #[cfg(feature = "ocr")]
    #[test]
    fn qr_image_secret_is_detected() {
        let payload = "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX";
        let png = qr_png(payload);
        let value = serde_json::json!(format!(
            "data:image/png;base64,{}",
            data_encoding::BASE64.encode(&png)
        ));
        let inspection = inspect_tool_images_for_secrets(&value, &[7; 32], &test_config()).unwrap();
        assert_eq!(inspection.scanned_images, 1);
        assert_eq!(inspection.secret_images, 1);
        assert_eq!(inspection.unscanned_images, 0);
    }

    #[cfg(feature = "ocr")]
    #[test]
    fn qr_image_plain_text_is_not_secret() {
        let png = qr_png("hello from pentect qr");
        let value = serde_json::json!(format!(
            "data:image/png;base64,{}",
            data_encoding::BASE64.encode(&png)
        ));
        let inspection = inspect_tool_images_for_secrets(&value, &[7; 32], &test_config()).unwrap();
        assert_eq!(inspection.scanned_images, 1);
        assert_eq!(inspection.secret_images, 0);
        assert_eq!(inspection.unscanned_images, 0);
    }

    #[test]
    fn image_scan_budget_limits_count_and_bytes() {
        let image =
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII=";
        let value = serde_json::json!([image, image]);

        let mut cfg = test_config();
        cfg.max_images = 1;
        let inspection = inspect_tool_images_for_secrets(&value, &[7; 32], &cfg).unwrap();
        assert_eq!(inspection.scanned_images, 1);
        assert_eq!(inspection.unscanned_images, 1);

        let mut cfg = test_config();
        cfg.max_image_bytes = 1;
        let inspection =
            inspect_tool_images_for_secrets(&serde_json::json!(image), &[7; 32], &cfg).unwrap();
        assert_eq!(inspection.scanned_images, 0);
        assert_eq!(inspection.unscanned_images, 1);

        let bytes = inline_image_bytes(image, test_config().max_image_bytes)
            .unwrap()
            .unwrap();
        let mut cfg = test_config();
        cfg.max_total_bytes = bytes.len() as u64 - 1;
        let inspection =
            inspect_tool_images_for_secrets(&serde_json::json!(image), &[7; 32], &cfg).unwrap();
        assert_eq!(inspection.scanned_images, 0);
        assert_eq!(inspection.unscanned_images, 1);
    }

    #[test]
    fn image_scan_budget_limits_elapsed_time() {
        let mut inspection = ImageInspection {
            scanned_images: 0,
            unscanned_images: 0,
            ocr_failures: 0,
            secret_images: 0,
            attempted_images: 0,
            total_image_bytes: 0,
            started_at: std::time::Instant::now() - std::time::Duration::from_secs(2),
        };
        let mut cfg = test_config();
        cfg.max_seconds = 1;
        assert!(!inspection.reserve_image_slot(&cfg));
    }

    #[test]
    fn remote_image_url_with_query_is_reference() {
        assert!(looks_like_image_reference(
            "https://example.test/images/screenshot.png?token=public#main"
        ));
    }

    #[cfg(feature = "ocr")]
    #[test]
    fn remote_image_url_bytes_are_downloaded() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let png = inline_image_bytes(
            "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII=",
            test_config().max_image_bytes,
        )
        .unwrap()
        .unwrap();

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                png.len()
            )
            .unwrap();
            stream.write_all(&png).unwrap();
        });

        let url = format!("http://{addr}/scan.png?cache=1");
        let bytes = fetch_image_url_bytes(
            &url,
            &test_config(),
            test_config().max_image_bytes,
            std::time::Instant::now() + std::time::Duration::from_secs(20),
        )
        .unwrap()
        .unwrap();
        assert_eq!(image_signature(&bytes), Some("png"));
        handle.join().unwrap();
    }

    #[cfg(feature = "ocr")]
    #[test]
    fn nested_remote_image_url_object_is_scanned() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let png = inline_image_bytes(
            "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII=",
            test_config().max_image_bytes,
        )
        .unwrap()
        .unwrap();

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                png.len()
            )
            .unwrap();
            stream.write_all(&png).unwrap();
        });

        let value = serde_json::json!({
            "type": "image_url",
            "image_url": {
                "url": format!("http://{addr}/nested.png")
            }
        });
        let inspection = inspect_tool_images_for_secrets(&value, &[7; 32], &test_config()).unwrap();
        assert_eq!(inspection.scanned_images, 1);
        assert_eq!(inspection.unscanned_images, 0);
        handle.join().unwrap();
    }

    #[cfg(feature = "ocr")]
    #[test]
    fn remote_image_redirect_is_validated_and_followed() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let image_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let image_addr = image_listener.local_addr().unwrap();
        let redirect_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let redirect_addr = redirect_listener.local_addr().unwrap();
        let png = inline_image_bytes(
            "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII=",
            test_config().max_image_bytes,
        )
        .unwrap()
        .unwrap();

        let image_handle = std::thread::spawn(move || {
            let (mut stream, _) = image_listener.accept().unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                png.len()
            )
            .unwrap();
            stream.write_all(&png).unwrap();
        });
        let redirect_handle = std::thread::spawn(move || {
            let (mut stream, _) = redirect_listener.accept().unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request);
            write!(
                stream,
                "HTTP/1.1 302 Found\r\nLocation: http://{image_addr}/final.png\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        });

        let url = format!("http://{redirect_addr}/start.png");
        let bytes = fetch_image_url_bytes(
            &url,
            &test_config(),
            test_config().max_image_bytes,
            std::time::Instant::now() + std::time::Duration::from_secs(20),
        )
        .unwrap()
        .unwrap();
        assert_eq!(image_signature(&bytes), Some("png"));
        redirect_handle.join().unwrap();
        image_handle.join().unwrap();
    }

    #[cfg(feature = "ocr")]
    #[test]
    fn failed_remote_image_url_is_unscanned() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request);
            write!(
                stream,
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        });

        let value = serde_json::json!(format!("http://{addr}/missing.png"));
        let inspection = inspect_tool_images_for_secrets(&value, &[7; 32], &test_config()).unwrap();
        assert_eq!(inspection.unscanned_images, 1);
        assert_eq!(inspection.scanned_images, 0);
        handle.join().unwrap();
    }

    #[cfg(feature = "ocr")]
    #[test]
    fn private_image_url_targets_are_recognized() {
        assert!(remote_image_ip_is_private("127.0.0.1".parse().unwrap()));
        assert!(remote_image_ip_is_private(
            "169.254.169.254".parse().unwrap()
        ));
        assert!(remote_image_ip_is_private("10.0.0.1".parse().unwrap()));
        assert!(!remote_image_ip_is_private("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn empty_ocr_text_is_not_secret() {
        assert!(image_text_secret_labels("", &[7; 32]).is_empty());
        assert!(image_text_secret_labels("   \n\t", &[7; 32]).is_empty());
    }

    #[cfg(all(feature = "ocr", target_os = "linux"))]
    #[test]
    fn resize_for_ocr_caps_long_edge() {
        use image::GenericImageView;

        let img = image::DynamicImage::new_rgb8(4096, 1024);
        let resized = resize_for_ocr(img, 2048);
        assert_eq!(resized.dimensions(), (2048, 512));

        let img = image::DynamicImage::new_rgb8(1024, 512);
        let resized = resize_for_ocr(img, 2048);
        assert_eq!(resized.dimensions(), (1024, 512));
    }

    #[cfg(all(feature = "ocr", target_os = "windows"))]
    #[test]
    fn windows_scaled_dimensions_cap_long_edge() {
        assert_eq!(scaled_dimensions(4096, 1024, 2048), (2048, 512));
        assert_eq!(scaled_dimensions(1024, 512, 2048), (1024, 512));
        assert_eq!(scaled_dimensions(10, 100, 50), (5, 50));
    }
}
