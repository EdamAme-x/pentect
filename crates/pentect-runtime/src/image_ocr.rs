#[cfg(feature = "ocr")]
use crate::config::{image_ocr_config, ImageOcrMode};
use serde_json::Value;

pub(crate) struct ImageInspection {
    pub(crate) inline_images: usize,
    pub(crate) unscanned_images: usize,
    pub(crate) ocr_failures: usize,
    pub(crate) secret_images: usize,
}

pub(crate) fn contains_image_result(value: &Value) -> bool {
    match value {
        Value::String(text) => looks_like_image_reference(text) || looks_like_base64_image(text),
        Value::Number(_) | Value::Bool(_) | Value::Null => false,
        Value::Array(items) => items.iter().any(contains_image_result),
        Value::Object(map) => object_marks_image(map) || map.values().any(contains_image_result),
    }
}

pub(crate) fn is_image_object(value: &Value) -> bool {
    value.as_object().is_some_and(object_marks_image)
}

pub(crate) fn skip_text_masking_for_image_payload(text: &str) -> bool {
    text.trim().to_ascii_lowercase().starts_with("data:image/") || looks_like_base64_image(text)
}

pub(crate) fn image_payload_field_key(key: &str) -> bool {
    matches!(
        normalized_json_key(key).as_str(),
        "data"
            | "bytes"
            | "base64"
            | "content"
            | "image"
            | "imagedata"
            | "imageurl"
            | "url"
            | "uri"
            | "src"
            | "href"
            | "dataurl"
    )
}

pub(crate) fn inspect_tool_images_for_secrets(
    value: &Value,
    key: &[u8; 32],
) -> Result<ImageInspection, String> {
    let mut inspection = ImageInspection {
        inline_images: 0,
        unscanned_images: 0,
        ocr_failures: 0,
        secret_images: 0,
    };
    collect_image_inspection(value, key, &mut inspection)?;
    Ok(inspection)
}

fn collect_image_inspection(
    value: &Value,
    key: &[u8; 32],
    inspection: &mut ImageInspection,
) -> Result<(), String> {
    match value {
        Value::String(text) => {
            if let Some(bytes) = inline_image_bytes(text)? {
                inspect_image_bytes(&bytes, key, inspection);
            } else if looks_like_image_reference(text) {
                inspection.unscanned_images += 1;
            }
        }
        Value::Number(_) | Value::Bool(_) | Value::Null => {}
        Value::Array(items) => {
            for item in items {
                collect_image_inspection(item, key, inspection)?;
            }
        }
        Value::Object(map) => {
            if object_marks_image(map) {
                if let Some(bytes) = inline_image_object_bytes(map)? {
                    inspect_image_bytes(&bytes, key, inspection);
                } else if !empty_image_object(map) {
                    inspection.unscanned_images += 1;
                }
                return Ok(());
            }
            for item in map.values() {
                collect_image_inspection(item, key, inspection)?;
            }
        }
    }
    Ok(())
}

fn inspect_image_bytes(bytes: &[u8], key: &[u8; 32], inspection: &mut ImageInspection) {
    inspection.inline_images += 1;
    match ocr_image_bytes(bytes) {
        Ok(text) => {
            if ocr_text_has_secret(&text, key) {
                inspection.secret_images += 1;
            }
        }
        Err(_) => {
            inspection.ocr_failures += 1;
        }
    }
}

fn ocr_text_has_secret(text: &str, key: &[u8; 32]) -> bool {
    if text.trim().is_empty() {
        return false;
    }
    let engine = pentect_core::Engine::with_profile(pentect_core::Profile::Strict);
    let result = engine.mask(
        pentect_core::Input {
            kind: pentect_core::Kind::Text,
            data: text.to_string(),
        },
        &pentect_core::Config::new(*key),
    );
    result.summary.masked_count > 0
}

fn object_marks_image(map: &serde_json::Map<String, Value>) -> bool {
    map.iter().any(|(key, value)| {
        let key = normalized_json_key(key);
        key_marks_image_value(&key, value) || string_image_field(&key, value)
    })
}

fn inline_image_object_bytes(
    map: &serde_json::Map<String, Value>,
) -> Result<Option<Vec<u8>>, String> {
    for key in [
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
    ] {
        let Some(text) = map.get(key).and_then(Value::as_str) else {
            continue;
        };
        if let Some(bytes) = inline_image_bytes(text)? {
            return Ok(Some(bytes));
        }
    }
    Ok(None)
}

fn inline_image_bytes(text: &str) -> Result<Option<Vec<u8>>, String> {
    let text = text.trim();
    if let Some(payload) = text
        .strip_prefix("data:image/")
        .and_then(|rest| rest.split_once(','))
        .and_then(|(meta, payload)| meta.contains(";base64").then_some(payload))
    {
        return decode_base64(payload).map(Some);
    }
    if looks_like_base64_image(text) {
        return decode_base64(text).map(Some);
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

fn decode_base64(text: &str) -> Result<Vec<u8>, String> {
    let compact = compact_base64(text);
    data_encoding::BASE64
        .decode(compact.as_bytes())
        .map_err(|e| format!("image base64 is invalid: {e}"))
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
        || value.ends_with(".png")
        || value.ends_with(".jpg")
        || value.ends_with(".jpeg")
        || value.ends_with(".webp")
        || value.ends_with(".gif")
        || value.ends_with(".bmp")
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
pub fn ocr_image_bytes(bytes: &[u8]) -> Result<String, String> {
    use image::GenericImageView;
    use ocrs::{ImageSource, OcrEngine, OcrEngineParams};
    use rten::Model;
    use std::sync::OnceLock;

    static ENGINE: OnceLock<Result<OcrEngine, String>> = OnceLock::new();

    let cfg = image_ocr_config()?;
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
    engine
        .get_text(&input)
        .map_err(|e| format!("could not OCR image: {e}"))
}

#[cfg(feature = "ocr")]
fn resize_for_ocr(img: image::DynamicImage, max_edge: u32) -> image::DynamicImage {
    use image::GenericImageView;

    let (width, height) = img.dimensions();
    if width <= max_edge && height <= max_edge {
        return img;
    }
    img.resize(max_edge, max_edge, image::imageops::FilterType::Triangle)
}

#[cfg(not(feature = "ocr"))]
pub fn ocr_image_bytes(_bytes: &[u8]) -> Result<String, String> {
    Err("image OCR requires a build with `--features ocr`".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_url_image_payload_is_decoded() {
        let png = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII=";
        let bytes = inline_image_bytes(png).unwrap().unwrap();
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
        assert!(inline_image_object_bytes(map).unwrap().is_some());
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
        assert!(inline_image_object_bytes(inner).unwrap().is_some());
    }

    #[test]
    fn empty_ocr_text_is_not_secret() {
        assert!(!ocr_text_has_secret("", &[7; 32]));
        assert!(!ocr_text_has_secret("   \n\t", &[7; 32]));
    }

    #[cfg(feature = "ocr")]
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
}
