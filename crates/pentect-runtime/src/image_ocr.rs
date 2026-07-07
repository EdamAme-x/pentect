use crate::config::ImageOcrConfig;
#[cfg(feature = "ocr")]
use crate::config::{image_ocr_config, ImageOcrMode};
use serde_json::Value;
#[cfg(feature = "ocr")]
use std::net::{IpAddr, SocketAddr};

#[cfg(feature = "ocr")]
const IMAGE_URL_MAX_REDIRECTS: usize = 5;

pub(crate) struct ImageInspection {
    pub(crate) scanned_images: usize,
    pub(crate) unscanned_images: usize,
    pub(crate) ocr_failures: usize,
    pub(crate) secret_images: usize,
    attempted_images: usize,
    total_image_bytes: u64,
    started_at: std::time::Instant,
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
    if image_barcode_texts(bytes, cfg)
        .iter()
        .any(|text| ocr_text_has_secret(text, key))
    {
        inspection.secret_images += 1;
        return;
    }
    match ocr_image_bytes_with_config(bytes, cfg) {
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

fn ocr_text_has_secret(text: &str, key: &[u8; 32]) -> bool {
    if text.trim().is_empty() {
        return false;
    }
    let engine = image_ocr_secret_engine();
    let result = engine.mask(
        pentect_core::Input {
            kind: pentect_core::Kind::Text,
            data: text.to_string(),
        },
        &pentect_core::Config::new(*key),
    );
    result.summary.masked_count > 0
}

#[cfg(feature = "ocr")]
fn image_barcode_texts(bytes: &[u8], cfg: &ImageOcrConfig) -> Vec<String> {
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
    let mut texts = Vec::new();
    for result in results {
        let text = result.getText();
        if !text.trim().is_empty() && !texts.iter().any(|seen| seen == text) {
            texts.push(text.to_string());
        }
    }
    texts
}

#[cfg(not(feature = "ocr"))]
fn image_barcode_texts(_bytes: &[u8], _cfg: &ImageOcrConfig) -> Vec<String> {
    Vec::new()
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
    result
        .Text()
        .map(|text| text.to_string_lossy())
        .map_err(|e| format!("could not read OCR text: {e}"))
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
        return Ok(String::new());
    };
    let mut text = String::new();
    for index in 0..observations.len() {
        let observation = observations.objectAtIndex(index);
        let candidates = observation.topCandidates(1);
        if candidates.is_empty() {
            continue;
        }
        let candidate = candidates.objectAtIndex(0);
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&candidate.string().to_string());
    }
    Ok(text)
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
    use image::GenericImageView;
    use ocrs::{ImageSource, OcrEngine, OcrEngineParams};
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

#[cfg(not(feature = "ocr"))]
pub fn ocr_image_bytes(_bytes: &[u8]) -> Result<String, String> {
    Err("image OCR requires a build with `--features ocr`".to_string())
}

#[cfg(not(feature = "ocr"))]
fn ocr_image_bytes_with_config(_bytes: &[u8], _cfg: &ImageOcrConfig) -> Result<String, String> {
    Err("image OCR requires a build with `--features ocr`".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ImageOcrMode, UnscannedImagePolicy};

    fn test_config() -> ImageOcrConfig {
        ImageOcrConfig {
            mode: ImageOcrMode::On,
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
        assert!(!ocr_text_has_secret("", &[7; 32]));
        assert!(!ocr_text_has_secret("   \n\t", &[7; 32]));
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
