#[cfg(feature = "ocr")]
use crate::config::{image_ocr_config, ImageOcrMode};
use serde_json::Value;
#[cfg(feature = "ocr")]
use std::net::IpAddr;

#[cfg(feature = "ocr")]
const IMAGE_URL_MAX_BYTES: u64 = 16 * 1024 * 1024;
#[cfg(feature = "ocr")]
const IMAGE_URL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub(crate) struct ImageInspection {
    pub(crate) scanned_images: usize,
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
        scanned_images: 0,
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
            if looks_like_image_reference(text) {
                match image_reference_bytes(text) {
                    Ok(Some(bytes)) => inspect_image_bytes(&bytes, key, inspection),
                    Ok(None) | Err(_) => inspection.unscanned_images += 1,
                }
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
                match image_object_bytes(map) {
                    Ok(Some(bytes)) => inspect_image_bytes(&bytes, key, inspection),
                    Ok(None) | Err(_) => {
                        if !empty_image_object(map) {
                            inspection.unscanned_images += 1;
                        }
                    }
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
    inspection.scanned_images += 1;
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

fn image_object_bytes(map: &serde_json::Map<String, Value>) -> Result<Option<Vec<u8>>, String> {
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
        if let Some(bytes) = image_reference_bytes(text)? {
            return Ok(Some(bytes));
        }
    }
    Ok(None)
}

fn image_reference_bytes(text: &str) -> Result<Option<Vec<u8>>, String> {
    if let Some(bytes) = inline_image_bytes(text)? {
        return Ok(Some(bytes));
    }
    fetch_image_url_bytes(text)
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
fn fetch_image_url_bytes(text: &str) -> Result<Option<Vec<u8>>, String> {
    use std::io::Read;
    use std::sync::OnceLock;

    let url = text.trim();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Ok(None);
    }
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("image URL is invalid: {e}"))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Ok(None);
    }
    validate_remote_image_url_target(&parsed)?;

    static CLIENT: OnceLock<Result<reqwest::blocking::Client, String>> = OnceLock::new();
    let client = CLIENT
        .get_or_init(|| {
            reqwest::blocking::Client::builder()
                .timeout(IMAGE_URL_TIMEOUT)
                .redirect(reqwest::redirect::Policy::limited(5))
                .build()
                .map_err(|e| format!("could not initialize image fetcher: {e}"))
        })
        .as_ref()
        .map_err(Clone::clone)?;

    let response = client
        .get(parsed)
        .send()
        .map_err(|e| format!("could not fetch image URL: {e}"))?;
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
    if response
        .content_length()
        .is_some_and(|len| len > IMAGE_URL_MAX_BYTES)
    {
        return Err(format!(
            "image URL is larger than {IMAGE_URL_MAX_BYTES} bytes"
        ));
    }

    let mut bytes = Vec::new();
    let mut limited = response.take(IMAGE_URL_MAX_BYTES + 1);
    limited
        .read_to_end(&mut bytes)
        .map_err(|e| format!("could not read image URL: {e}"))?;
    if bytes.len() as u64 > IMAGE_URL_MAX_BYTES {
        return Err(format!(
            "image URL is larger than {IMAGE_URL_MAX_BYTES} bytes"
        ));
    }
    if image_signature(&bytes).is_none() {
        return Err("image URL did not return a supported image".to_string());
    }
    Ok(Some(bytes))
}

#[cfg(feature = "ocr")]
fn validate_remote_image_url_target(url: &reqwest::Url) -> Result<(), String> {
    use std::net::ToSocketAddrs;

    let host = url
        .host_str()
        .ok_or_else(|| "image URL has no host".to_string())?;
    let host_lc = host.to_ascii_lowercase();
    if host_lc == "localhost" || host_lc.ends_with(".localhost") {
        return local_image_url_result();
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return validate_remote_image_ip(ip);
    }

    let port = url
        .port_or_known_default()
        .ok_or_else(|| "image URL has no port".to_string())?;
    let mut saw_addr = false;
    for addr in (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("could not resolve image URL host: {e}"))?
    {
        saw_addr = true;
        validate_remote_image_ip(addr.ip())?;
    }
    if !saw_addr {
        return Err("image URL host did not resolve".to_string());
    }
    Ok(())
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
fn fetch_image_url_bytes(_text: &str) -> Result<Option<Vec<u8>>, String> {
    Ok(None)
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
        assert!(image_object_bytes(map).unwrap().is_some());
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
        assert!(image_object_bytes(inner).unwrap().is_some());
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
        let bytes = fetch_image_url_bytes(&url).unwrap().unwrap();
        assert_eq!(image_signature(&bytes), Some("png"));
        handle.join().unwrap();
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
        let inspection = inspect_tool_images_for_secrets(&value, &[7; 32]).unwrap();
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
