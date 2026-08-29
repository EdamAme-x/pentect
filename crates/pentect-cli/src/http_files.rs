//! File-upload protection shared by the HTTP gateways.
//!
//! Only UTF-8 text formats are rewritten here. Binary formats require a
//! format-aware rewriter; treating arbitrary bytes as text would corrupt them
//! while pretending they were protected.

use hyper::body::Bytes;
use memchr::memmem;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

const MAX_MULTIPART_BYTES: usize = 32 * 1024 * 1024;
const MAX_MULTIPART_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_MULTIPART_PARTS: usize = 64;
const MAX_MULTIPART_FILES: usize = 16;
const MAX_MULTIPART_HEADER_BYTES: usize = 64 * 1024;
const MAX_MULTIPART_FIELD_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Coverage {
    Full,
    Partial,
    None,
}

impl Coverage {
    pub(crate) fn as_header(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Partial => "partial",
            Self::None => "none",
        }
    }
}

pub(crate) struct ProtectedUpload {
    pub(crate) body: Bytes,
    pub(crate) coverage: Coverage,
}

#[cfg(test)]
pub(crate) fn protect_multipart_upload(
    content_type: &str,
    body: &Bytes,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
) -> Result<ProtectedUpload, String> {
    protect_multipart_upload_with_plugins(
        content_type,
        body,
        masker,
        &pentect_agent::PluginMiddleware::default(),
    )
}

pub(crate) fn protect_multipart_upload_with_plugins(
    content_type: &str,
    body: &Bytes,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
    plugins: &pentect_agent::PluginMiddleware,
) -> Result<ProtectedUpload, String> {
    protect_multipart_upload_with_mode(
        content_type,
        body,
        masker,
        plugins,
        MultipartUploadMode::Files,
    )
}

pub(crate) fn protect_audio_multipart_upload_with_plugins(
    content_type: &str,
    body: &Bytes,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
    plugins: &pentect_agent::PluginMiddleware,
    block_uninspectable_audio: bool,
) -> Result<ProtectedUpload, String> {
    protect_multipart_upload_with_mode(
        content_type,
        body,
        masker,
        plugins,
        MultipartUploadMode::Audio {
            block_uninspectable_audio,
        },
    )
}

#[derive(Clone, Copy)]
enum MultipartUploadMode {
    Files,
    Audio { block_uninspectable_audio: bool },
}

fn protect_multipart_upload_with_mode(
    content_type: &str,
    body: &Bytes,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
    plugins: &pentect_agent::PluginMiddleware,
    mode: MultipartUploadMode,
) -> Result<ProtectedUpload, String> {
    if body.len() > MAX_MULTIPART_BYTES {
        return Err("file upload blocked: multipart request is too large".to_string());
    }
    let boundary = multipart_boundary(content_type)
        .ok_or_else(|| "Files API upload is missing a multipart boundary".to_string())?;
    let delimiter = format!("--{boundary}").into_bytes();
    let body_separator = b"\r\n\r\n";
    let mut next_part_prefix = Vec::with_capacity(delimiter.len() + 2);
    next_part_prefix.extend_from_slice(b"\r\n");
    next_part_prefix.extend_from_slice(&delimiter);
    let purpose = multipart_field(body, &delimiter, &next_part_prefix, "purpose");
    let immutable_dataset = matches!(mode, MultipartUploadMode::Files)
        && purpose
            .as_deref()
            .is_some_and(|purpose| matches!(purpose, "batch" | "fine-tune" | "evals"));
    let mut cursor = 0;
    let mut output = Vec::with_capacity(body.len());
    let mut saw_file = false;
    let mut coverage = Coverage::Full;
    let mut plugin_partial = false;
    let mut part_count = 0usize;
    let mut file_count = 0usize;
    let mut field_bytes = 0usize;

    while let Some(relative_start) = memmem::find(&body[cursor..], &delimiter) {
        let part_start = cursor + relative_start;
        output.extend_from_slice(&body[cursor..part_start]);
        let after_delimiter = part_start + delimiter.len();
        output.extend_from_slice(&body[part_start..after_delimiter]);
        cursor = after_delimiter;

        if body.get(cursor..cursor + 2) == Some(b"--") {
            output.extend_from_slice(&body[cursor..]);
            cursor = body.len();
            break;
        }
        if body.get(cursor..cursor + 2) != Some(b"\r\n") {
            return Err("file upload blocked: malformed multipart body".to_string());
        }

        let headers_start = cursor + 2;
        let Some(headers_relative_end) = memmem::find(&body[headers_start..], body_separator)
        else {
            return Err("file upload blocked: malformed multipart headers".to_string());
        };
        let headers_end = headers_start + headers_relative_end;
        if headers_end - headers_start > MAX_MULTIPART_HEADER_BYTES {
            return Err("file upload blocked: multipart headers are too large".to_string());
        }
        part_count = part_count.saturating_add(1);
        if part_count > MAX_MULTIPART_PARTS {
            return Err("file upload blocked: multipart request has too many parts".to_string());
        }
        let content_start = headers_end + body_separator.len();
        let Some(content_relative_end) = memmem::find(&body[content_start..], &next_part_prefix)
        else {
            return Err("file upload blocked: unterminated multipart file".to_string());
        };
        let content_end = content_start + content_relative_end;
        let headers = &body[headers_start..headers_end];
        let content = &body[content_start..content_end];

        output.extend_from_slice(&body[cursor..headers_start]);
        if let Some(file) = file_part(headers) {
            file_count = file_count.saturating_add(1);
            if file_count > MAX_MULTIPART_FILES {
                return Err("file upload blocked: multipart request has too many files".to_string());
            }
            saw_file = true;
            let metadata = serde_json::json!({
                "filename": file.filename,
                "media_type": file.media_type,
                "size": content.len(),
            });
            run_file_stage(
                plugins,
                pentect_agent::MiddlewareStage::File,
                metadata,
                &mut plugin_partial,
            )?;
            if file.is_supported_text {
                output.extend_from_slice(headers);
                output.extend_from_slice(body_separator);
                match std::str::from_utf8(content) {
                    Ok(text) => match masker.mask_tool_output(text) {
                        Ok(Some(masked)) => {
                            let final_masked =
                                masker.mask_tool_output(&masked)?.ok_or_else(|| {
                                    "file upload blocked: text inspection is unavailable"
                                        .to_string()
                                })?;
                            if immutable_dataset && final_masked != text {
                                return Err(
                                    "file upload blocked: secret detected in a structured dataset"
                                        .to_string(),
                                );
                            }
                            extend_protected_output(&mut output, final_masked.as_bytes())?;
                        }
                        Ok(None) => {
                            return Err(
                                "file upload blocked: text inspection is unavailable".to_string()
                            );
                        }
                        Err(error) => {
                            return Err(format!("file upload blocked: {error}"));
                        }
                    },
                    Err(_) => {
                        return Err(
                            "file upload blocked: declared text is not valid UTF-8".to_string()
                        );
                    }
                }
            } else if file.is_supported_image {
                let protected = pentect_agent::redact_image_bytes_into_active_memory_store(content)
                    .map_err(|error| format!("file upload blocked: {error}"))?;
                if let Some(mut protected) = protected {
                    let media_type = image_media_type(&protected.bytes).ok_or_else(|| {
                        "file upload blocked: protected image has an unknown format".to_string()
                    })?;
                    output.extend_from_slice(
                        &headers_with_media_type(headers, media_type).ok_or_else(|| {
                            "file upload blocked: invalid image headers".to_string()
                        })?,
                    );
                    output.extend_from_slice(body_separator);
                    extend_protected_output(&mut output, &protected.bytes)?;
                    protected.bytes.zeroize();
                    // A Files API upload has no adjacent model-visible text
                    // block in which to carry the opaque handles.
                    coverage = Coverage::Partial;
                } else {
                    output.extend_from_slice(headers);
                    output.extend_from_slice(body_separator);
                    output.extend_from_slice(content);
                }
            } else if matches!(mode, MultipartUploadMode::Audio { .. })
                && supported_audio_file(&file.filename, file.media_type.as_deref())
            {
                if matches!(
                    mode,
                    MultipartUploadMode::Audio {
                        block_uninspectable_audio: true
                    }
                ) {
                    return Err(
                        "unknown format blocked: OpenAI audio content cannot be inspected safely; set compatibility.unknown_formats = \"ignore\" to pass the audio through while still protecting text fields"
                            .to_string(),
                    );
                }
                output.extend_from_slice(headers);
                output.extend_from_slice(body_separator);
                output.extend_from_slice(content);
                coverage = Coverage::Partial;
            } else {
                return Err(
                    "file upload blocked: this binary format cannot be inspected safely"
                        .to_string(),
                );
            }
        } else {
            field_bytes = field_bytes.saturating_add(content.len());
            if field_bytes > MAX_MULTIPART_FIELD_BYTES {
                return Err("file upload blocked: multipart fields are too large".to_string());
            }
            output.extend_from_slice(headers);
            output.extend_from_slice(body_separator);
            if matches!(mode, MultipartUploadMode::Audio { .. })
                && multipart_part_name(headers).as_deref() == Some("prompt")
            {
                let text = std::str::from_utf8(content).map_err(|_| {
                    "file upload blocked: audio prompt is not valid UTF-8".to_string()
                })?;
                let masked = masker.mask_tool_output(text)?.ok_or_else(|| {
                    "file upload blocked: audio prompt inspection is unavailable".to_string()
                })?;
                extend_protected_output(&mut output, masked.as_bytes())?;
            } else {
                output.extend_from_slice(content);
            }
        }
        cursor = content_end;
    }

    if cursor < body.len() {
        output.extend_from_slice(&body[cursor..]);
    }
    if matches!(mode, MultipartUploadMode::Audio { .. }) && !saw_file {
        return Err("file upload blocked: OpenAI audio request has no file part".to_string());
    }
    if !saw_file {
        coverage = Coverage::None;
    } else if plugin_partial {
        coverage = Coverage::Partial;
    }
    if output.len() > MAX_MULTIPART_OUTPUT_BYTES {
        output.zeroize();
        return Err("file upload blocked: protected multipart request is too large".to_string());
    }
    Ok(ProtectedUpload {
        body: Bytes::from(output),
        coverage,
    })
}

fn multipart_field(
    body: &[u8],
    delimiter: &[u8],
    next_part_prefix: &[u8],
    expected: &str,
) -> Option<String> {
    let mut cursor = 0;
    while let Some(relative_start) = memmem::find(&body[cursor..], delimiter) {
        let after_delimiter = cursor + relative_start + delimiter.len();
        if body.get(after_delimiter..after_delimiter + 2) == Some(b"--") {
            break;
        }
        let headers_start = after_delimiter.checked_add(2)?;
        if body.get(after_delimiter..headers_start) != Some(b"\r\n") {
            return None;
        }
        let headers_relative_end = memmem::find(&body[headers_start..], b"\r\n\r\n")?;
        let headers_end = headers_start + headers_relative_end;
        let content_start = headers_end + 4;
        let content_relative_end = memmem::find(&body[content_start..], next_part_prefix)?;
        let content_end = content_start + content_relative_end;
        let headers = std::str::from_utf8(&body[headers_start..headers_end]).ok()?;
        let disposition = headers.lines().find(|line| {
            line.to_ascii_lowercase()
                .starts_with("content-disposition:")
        })?;
        if disposition_parameter(disposition, "filename").is_none()
            && disposition_parameter(disposition, "name").as_deref() == Some(expected)
        {
            return std::str::from_utf8(&body[content_start..content_end])
                .ok()
                .map(|value| value.trim().to_string());
        }
        cursor = content_end;
    }
    None
}

pub(crate) fn multipart_text_field(
    content_type: &str,
    body: &[u8],
    expected: &str,
) -> Option<String> {
    let boundary = multipart_boundary(content_type)?;
    let delimiter = format!("--{boundary}").into_bytes();
    let mut next_part_prefix = Vec::with_capacity(delimiter.len() + 2);
    next_part_prefix.extend_from_slice(b"\r\n");
    next_part_prefix.extend_from_slice(&delimiter);
    multipart_field(body, &delimiter, &next_part_prefix, expected)
}

pub(crate) fn multipart_file_name(content_type: &str, body: &[u8]) -> Option<String> {
    let boundary = multipart_boundary(content_type)?;
    let delimiter = format!("--{boundary}").into_bytes();
    let mut cursor = 0;
    while let Some(relative_start) = memmem::find(&body[cursor..], &delimiter) {
        let after_delimiter = cursor + relative_start + delimiter.len();
        if body.get(after_delimiter..after_delimiter + 2) == Some(b"--") {
            break;
        }
        let headers_start = after_delimiter.checked_add(2)?;
        if body.get(after_delimiter..headers_start) != Some(b"\r\n") {
            return None;
        }
        let headers_relative_end = memmem::find(&body[headers_start..], b"\r\n\r\n")?;
        let headers_end = headers_start + headers_relative_end;
        if let Some(file) = file_part(&body[headers_start..headers_end]) {
            return Some(file.filename);
        }
        cursor = headers_end + 4;
    }
    None
}

fn multipart_boundary(content_type: &str) -> Option<String> {
    if !content_type
        .split(';')
        .next()?
        .trim()
        .eq_ignore_ascii_case("multipart/form-data")
    {
        return None;
    }
    content_type.split(';').skip(1).find_map(|parameter| {
        let (name, value) = parameter.trim().split_once('=')?;
        if !name.trim().eq_ignore_ascii_case("boundary") {
            return None;
        }
        let value = value.trim().trim_matches('"');
        (!value.is_empty() && value.len() <= 200).then(|| value.to_string())
    })
}

struct FilePart {
    is_supported_text: bool,
    is_supported_image: bool,
    filename: String,
    media_type: Option<String>,
}

fn file_part(headers: &[u8]) -> Option<FilePart> {
    let headers = std::str::from_utf8(headers).ok()?;
    let disposition = headers.lines().find(|line| {
        line.to_ascii_lowercase()
            .starts_with("content-disposition:")
    })?;
    let filename = disposition_parameter(disposition, "filename")?;
    let media_type = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-type")
            .then(|| value.trim().split(';').next().unwrap_or("").trim())
    });
    Some(FilePart {
        is_supported_text: supported_text_file(&filename, media_type),
        is_supported_image: supported_image_file(&filename, media_type),
        filename,
        media_type: media_type.map(str::to_string),
    })
}

fn supported_image_file(filename: &str, media_type: Option<&str>) -> bool {
    if media_type.is_some_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "image/png" | "image/jpeg" | "image/webp" | "image/gif" | "image/bmp"
        )
    }) {
        return true;
    }
    Path::new(filename)
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "png" | "jpg" | "jpeg" | "webp" | "gif" | "bmp"
            )
        })
}

fn supported_audio_file(filename: &str, media_type: Option<&str>) -> bool {
    if media_type.is_some_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "audio/flac"
                | "audio/mpeg"
                | "audio/mp4"
                | "audio/mpga"
                | "audio/m4a"
                | "audio/ogg"
                | "audio/wav"
                | "audio/x-wav"
                | "audio/webm"
                | "video/mp4"
                | "video/webm"
        )
    }) {
        return true;
    }
    Path::new(filename)
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "flac" | "mp3" | "mp4" | "mpeg" | "mpga" | "m4a" | "ogg" | "wav" | "webm"
            )
        })
}

fn multipart_part_name(headers: &[u8]) -> Option<String> {
    let headers = std::str::from_utf8(headers).ok()?;
    let disposition = headers.lines().find(|line| {
        line.to_ascii_lowercase()
            .starts_with("content-disposition:")
    })?;
    disposition_parameter(disposition, "name")
}

fn image_media_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
        Some("image/webp")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.starts_with(b"BM") {
        Some("image/bmp")
    } else {
        None
    }
}

fn headers_with_media_type(headers: &[u8], media_type: &str) -> Option<Vec<u8>> {
    let headers = std::str::from_utf8(headers).ok()?;
    let mut out = String::with_capacity(headers.len());
    let mut replaced = false;
    for (index, line) in headers.lines().enumerate() {
        if index > 0 {
            out.push_str("\r\n");
        }
        if line
            .split_once(':')
            .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case("content-type"))
        {
            out.push_str("Content-Type: ");
            out.push_str(media_type);
            replaced = true;
        } else {
            out.push_str(line);
        }
    }
    if !replaced {
        out.push_str("\r\nContent-Type: ");
        out.push_str(media_type);
    }
    Some(out.into_bytes())
}

fn run_file_stage(
    plugins: &pentect_agent::PluginMiddleware,
    stage: pentect_agent::MiddlewareStage,
    payload: serde_json::Value,
    partial: &mut bool,
) -> Result<serde_json::Value, String> {
    let run = plugins.run(
        stage,
        payload,
        Some(serde_json::json!({"transport": "http_multipart"})),
    )?;
    *partial |= run.coverage == pentect_agent::MiddlewareCoverage::Partial;
    if run.stopped.is_some() {
        return Err(format!(
            "file upload blocked: {}",
            run.message
                .unwrap_or_else(|| "blocked by plugin".to_string())
        ));
    }
    Ok(run.payload)
}

#[derive(Debug, PartialEq, Eq)]
struct InlineFileMetadata {
    filename: Option<String>,
    media_type: String,
    size: usize,
}

pub(crate) fn run_anthropic_inline_file_stages(
    value: &serde_json::Value,
    plugins: &pentect_agent::PluginMiddleware,
    provider: &str,
    transport: &str,
) -> Result<bool, String> {
    let mut files = Vec::new();
    collect_anthropic_inline_files(value, &mut files);
    run_inline_file_stages(files, plugins, provider, transport)
}

pub(crate) fn run_google_inline_file_stages(
    value: &serde_json::Value,
    plugins: &pentect_agent::PluginMiddleware,
    provider: &str,
    transport: &str,
) -> Result<bool, String> {
    let mut files = Vec::new();
    collect_google_inline_files(value, &mut files);
    run_inline_file_stages(files, plugins, provider, transport)
}

fn run_inline_file_stages(
    files: Vec<InlineFileMetadata>,
    plugins: &pentect_agent::PluginMiddleware,
    provider: &str,
    transport: &str,
) -> Result<bool, String> {
    let mut partial = false;
    for file in files {
        let run = plugins.run(
            pentect_agent::MiddlewareStage::File,
            serde_json::json!({
                "filename": file.filename,
                "media_type": file.media_type,
                "size": file.size,
            }),
            Some(serde_json::json!({
                "provider": provider,
                "transport": transport,
                "inline": true,
                "encoding": "base64",
            })),
        )?;
        partial |= run.coverage == pentect_agent::MiddlewareCoverage::Partial;
        if run.stopped.is_some() {
            return Err(format!(
                "file upload blocked: {}",
                run.message
                    .unwrap_or_else(|| "blocked by plugin".to_string())
            ));
        }
    }
    Ok(partial)
}

fn collect_anthropic_inline_files(value: &serde_json::Value, output: &mut Vec<InlineFileMetadata>) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                collect_anthropic_inline_files(value, output);
            }
        }
        serde_json::Value::Object(object) => {
            let kind = object
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if matches!(kind, "document" | "image") {
                if let Some(source) = object.get("source").and_then(serde_json::Value::as_object) {
                    if source.get("type").and_then(serde_json::Value::as_str) == Some("base64") {
                        push_inline_file(
                            output,
                            object_filename(object),
                            source
                                .get("media_type")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("application/octet-stream"),
                            source.get("data").and_then(serde_json::Value::as_str),
                        );
                    }
                } else if let Some((field, data)) = ["file_data", "image_url", "url", "data"]
                    .into_iter()
                    .find_map(|key| {
                        object
                            .get(key)
                            .and_then(serde_json::Value::as_str)
                            .map(|data| (key, data))
                    })
                {
                    if data.starts_with("data:") {
                        push_data_uri_file(output, object_filename(object), data);
                    } else if matches!(field, "file_data" | "data") {
                        push_inline_file(
                            output,
                            object_filename(object),
                            object_media_type(object),
                            Some(data),
                        );
                    }
                }
                return;
            }
            if matches!(kind, "tool_use" | "mcp_tool_use" | "server_tool_use") {
                return;
            }
            for child in object.values() {
                collect_anthropic_inline_files(child, output);
            }
        }
        _ => {}
    }
}

fn collect_google_inline_files(value: &serde_json::Value, output: &mut Vec<InlineFileMetadata>) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                collect_google_inline_files(value, output);
            }
        }
        serde_json::Value::Object(object) => {
            if let Some(inline) = object
                .get("inlineData")
                .and_then(serde_json::Value::as_object)
            {
                push_inline_file(
                    output,
                    None,
                    inline
                        .get("mimeType")
                        .or_else(|| inline.get("mime_type"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("application/octet-stream"),
                    inline.get("data").and_then(serde_json::Value::as_str),
                );
            }
            for (key, child) in object {
                if !matches!(
                    key.as_str(),
                    "inlineData" | "functionCall" | "functionResponse"
                ) {
                    collect_google_inline_files(child, output);
                }
            }
        }
        _ => {}
    }
}

fn object_filename(object: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    ["filename", "file_name", "name"]
        .into_iter()
        .find_map(|key| object.get(key).and_then(serde_json::Value::as_str))
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn object_media_type(object: &serde_json::Map<String, serde_json::Value>) -> &str {
    ["media_type", "mime_type", "mimeType"]
        .into_iter()
        .find_map(|key| object.get(key).and_then(serde_json::Value::as_str))
        .filter(|value| !value.is_empty())
        .unwrap_or("application/octet-stream")
}

fn push_data_uri_file(output: &mut Vec<InlineFileMetadata>, filename: Option<String>, data: &str) {
    let Some((metadata, encoded)) = data.split_once(',') else {
        return;
    };
    let Some(media_type) = metadata
        .strip_prefix("data:")
        .and_then(|metadata| metadata.strip_suffix(";base64"))
    else {
        return;
    };
    push_inline_file(output, filename, media_type, Some(encoded));
}

fn push_inline_file(
    output: &mut Vec<InlineFileMetadata>,
    filename: Option<String>,
    media_type: &str,
    encoded: Option<&str>,
) {
    let Some(encoded) = encoded else {
        return;
    };
    let Ok(max_size) = data_encoding::BASE64.decode_len(encoded.len()) else {
        return;
    };
    let padding = encoded
        .as_bytes()
        .iter()
        .rev()
        .take_while(|byte| **byte == b'=')
        .count()
        .min(2);
    let Some(size) = max_size.checked_sub(padding) else {
        return;
    };
    output.push(InlineFileMetadata {
        filename,
        media_type: media_type.to_string(),
        size,
    });
}

fn extend_protected_output(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_MULTIPART_OUTPUT_BYTES.saturating_sub(output.len()) {
        output.zeroize();
        return Err("file upload blocked: protected multipart request is too large".to_string());
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn disposition_parameter(header: &str, expected: &str) -> Option<String> {
    header.split(';').skip(1).find_map(|parameter| {
        let (name, value) = parameter.trim().split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case(expected)
            .then(|| value.trim().trim_matches('"').to_string())
    })
}

const MAX_TRACKED_FILE_IDS: usize = 1024;

const ATTESTATION_VERSION: u8 = 2;
const ATTESTATION_KEY_BYTES: usize = 32;
const DEFAULT_ATTESTATION_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const MAX_ATTESTATION_RECORDS: usize = 4096;
const MAX_ATTESTATION_RECORD_BYTES: usize = 16 * 1024;

/// Persistent, locally authenticated proof that a remote file ID refers to an
/// upload Pentect inspected. Provider, upstream, and a keyed credential scope
/// are part of the proof so a colliding ID cannot inherit coverage.
#[derive(Clone)]
pub(crate) struct FileAttestationStore {
    root: PathBuf,
    key: [u8; ATTESTATION_KEY_BYTES],
}

#[derive(Debug, Deserialize, Serialize)]
struct FileAttestation {
    version: u8,
    provider: String,
    upstream_hash: String,
    account_scope: String,
    file_id: String,
    coverage: Coverage,
    expires_at: u64,
    mac: String,
}

impl FileAttestationStore {
    /// Returns a keyed digest of ephemeral credential material. The material
    /// itself is neither retained nor serialized.
    pub(crate) fn account_scope(&self, material: &[u8]) -> String {
        mac_hex(&self.key, material)
    }

    pub(crate) fn account_scope_for_app_headers(&self, headers: &hyper::HeaderMap) -> String {
        let mut fields = headers
            .iter()
            .filter(|(name, _)| crate::upstream::is_origin_auth_header(name.as_str()))
            .map(|(name, value)| {
                (
                    name.as_str().to_ascii_lowercase().into_bytes(),
                    value.as_bytes().to_vec(),
                )
            })
            .collect::<Vec<_>>();
        fields.sort();
        let mut material = zeroize::Zeroizing::new(Vec::new());
        for (name, value) in fields {
            append_field(&mut material, &name);
            append_field(&mut material, &value);
        }
        self.account_scope(&material)
    }

    pub(crate) fn open_default() -> Result<Self, String> {
        #[cfg(target_os = "windows")]
        let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
        #[cfg(target_os = "macos")]
        let base = home_directory().map(|home| home.join("Library").join("Application Support"));
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        let base = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| home_directory().map(|home| home.join(".local").join("state")));
        let root = base
            .map(|base| base.join("pentect").join("file-attestations"))
            .ok_or_else(|| "could not find a local state directory for Pentect".to_string())?;
        Self::open(root)
    }

    pub(crate) fn open(root: impl AsRef<Path>) -> Result<Self, String> {
        let root = root.as_ref().to_path_buf();
        create_private_directory(&root)?;
        let key = load_or_create_attestation_key(&root.join("attestation.key"))?;
        create_private_directory(&root.join("records"))?;
        Ok(Self { root, key })
    }

    pub(crate) fn remember(
        &self,
        provider: &str,
        upstream: &str,
        account_scope: &str,
        file_id: &str,
        coverage: Coverage,
    ) -> Result<(), String> {
        self.remember_for(
            provider,
            upstream,
            account_scope,
            file_id,
            coverage,
            DEFAULT_ATTESTATION_TTL,
        )
    }

    pub(crate) async fn remember_async(
        &self,
        provider: &str,
        upstream: &str,
        account_scope: &str,
        file_id: &str,
        coverage: Coverage,
    ) -> Result<(), String> {
        let store = self.clone();
        let provider = provider.to_string();
        let upstream = upstream.to_string();
        let account_scope = account_scope.to_string();
        let file_id = file_id.to_string();
        tokio::task::spawn_blocking(move || {
            store.remember(&provider, &upstream, &account_scope, &file_id, coverage)
        })
        .await
        .map_err(|_| "file attestation task failed".to_string())?
    }

    fn remember_for(
        &self,
        provider: &str,
        upstream: &str,
        account_scope: &str,
        file_id: &str,
        coverage: Coverage,
        ttl: Duration,
    ) -> Result<(), String> {
        validate_attestation_component("provider", provider, 128)?;
        validate_attestation_component("file ID", file_id, 1024)?;
        validate_attestation_component("upstream", upstream, 4096)?;
        validate_attestation_scope(account_scope)?;
        let upstream_hash = digest_hex(upstream.as_bytes());
        let expires_at = unix_time()
            .checked_add(ttl.as_secs())
            .ok_or_else(|| "file attestation expiry overflowed".to_string())?;
        let mut record = FileAttestation {
            version: ATTESTATION_VERSION,
            provider: provider.to_string(),
            upstream_hash,
            account_scope: account_scope.to_string(),
            file_id: file_id.to_string(),
            coverage,
            expires_at,
            mac: String::new(),
        };
        record.mac = mac_hex(&self.key, &attestation_payload(&record));
        let bytes = serde_json::to_vec(&record)
            .map_err(|error| format!("could not encode file attestation: {error}"))?;
        let path = self.record_path(provider, upstream, account_scope, file_id);
        atomic_private_write(&path, &bytes)?;
        self.prune()?;
        Ok(())
    }

    pub(crate) fn coverage(
        &self,
        provider: &str,
        upstream: &str,
        account_scope: &str,
        file_id: &str,
    ) -> Result<Option<Coverage>, String> {
        validate_attestation_component("provider", provider, 128)?;
        validate_attestation_component("file ID", file_id, 1024)?;
        validate_attestation_component("upstream", upstream, 4096)?;
        validate_attestation_scope(account_scope)?;
        let path = self.record_path(provider, upstream, account_scope, file_id);
        let file = match OpenOptions::new().read(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("could not open file attestation: {error}")),
        };
        let mut bytes = Vec::new();
        file.take(MAX_ATTESTATION_RECORD_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("could not read file attestation: {error}"))?;
        if bytes.len() > MAX_ATTESTATION_RECORD_BYTES {
            let _ = fs::remove_file(path);
            return Ok(None);
        }
        let record: FileAttestation = match serde_json::from_slice(&bytes) {
            Ok(record) => record,
            Err(_) => {
                let _ = fs::remove_file(path);
                return Ok(None);
            }
        };
        let expected_upstream = digest_hex(upstream.as_bytes());
        let expected_mac = mac_bytes(&self.key, &attestation_payload(&record));
        let supplied_mac = match data_encoding::HEXLOWER.decode(record.mac.as_bytes()) {
            Ok(mac) => mac,
            Err(_) => {
                let _ = fs::remove_file(path);
                return Ok(None);
            }
        };
        let valid = record.version == ATTESTATION_VERSION
            && record.provider == provider
            && record.upstream_hash == expected_upstream
            && record.account_scope == account_scope
            && record.file_id == file_id
            && record.expires_at >= unix_time()
            && constant_time_eq(&expected_mac, &supplied_mac);
        if !valid {
            let _ = fs::remove_file(path);
            return Ok(None);
        }
        Ok(Some(record.coverage))
    }

    pub(crate) fn coverages_in_json(
        &self,
        body: &[u8],
        provider: &str,
        upstream: &str,
        account_scope: &str,
    ) -> Result<Vec<(String, Coverage)>, String> {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
            return Ok(Vec::new());
        };
        let mut ids = Vec::new();
        collect_json_file_ids(&value, &mut ids);
        let mut coverages = Vec::new();
        for id in ids {
            if let Some(coverage) = self.coverage(provider, upstream, account_scope, &id)? {
                coverages.push((id, coverage));
            }
        }
        Ok(coverages)
    }

    fn record_path(
        &self,
        provider: &str,
        upstream: &str,
        account_scope: &str,
        file_id: &str,
    ) -> PathBuf {
        let mut identity = Vec::with_capacity(
            provider.len() + upstream.len() + account_scope.len() + file_id.len() + 4,
        );
        append_field(&mut identity, provider.as_bytes());
        append_field(&mut identity, upstream.as_bytes());
        append_field(&mut identity, account_scope.as_bytes());
        append_field(&mut identity, file_id.as_bytes());
        self.root
            .join("records")
            .join(format!("{}.json", digest_hex(&identity)))
    }

    fn prune(&self) -> Result<(), String> {
        let mut entries = fs::read_dir(self.root.join("records"))
            .map_err(|error| format!("could not inspect file attestations: {error}"))?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let metadata = entry.metadata().ok()?;
                metadata
                    .is_file()
                    .then(|| (metadata.modified().unwrap_or(UNIX_EPOCH), entry.path()))
            })
            .collect::<Vec<_>>();
        if entries.len() <= MAX_ATTESTATION_RECORDS {
            return Ok(());
        }
        entries.sort_by_key(|(modified, _)| *modified);
        let remove = entries.len() - MAX_ATTESTATION_RECORDS;
        for (_, path) in entries.into_iter().take(remove) {
            let _ = fs::remove_file(path);
        }
        Ok(())
    }
}

fn validate_attestation_scope(scope: &str) -> Result<(), String> {
    if scope.len() != 64 || !scope.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("file attestation account scope is invalid".to_string());
    }
    Ok(())
}

fn collect_json_file_ids(value: &serde_json::Value, ids: &mut Vec<String>) {
    if ids.len() >= MAX_TRACKED_FILE_IDS {
        return;
    }
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                collect_json_file_ids(value, ids);
            }
        }
        serde_json::Value::Object(object) => {
            for key in ["file_id", "file_uuid"] {
                if let Some(id) = object.get(key).and_then(serde_json::Value::as_str) {
                    if !id.is_empty() && id.len() <= 1024 && !ids.iter().any(|known| known == id) {
                        ids.push(id.to_string());
                    }
                }
            }
            for value in object.values() {
                collect_json_file_ids(value, ids);
            }
        }
        _ => {}
    }
}

#[cfg(not(target_os = "windows"))]
fn home_directory() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

impl Drop for FileAttestationStore {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn validate_attestation_component(name: &str, value: &str, max: usize) -> Result<(), String> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(format!("file attestation {name} is invalid"));
    }
    Ok(())
}

fn attestation_payload(record: &FileAttestation) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(record.version);
    append_field(&mut payload, record.provider.as_bytes());
    append_field(&mut payload, record.upstream_hash.as_bytes());
    append_field(&mut payload, record.account_scope.as_bytes());
    append_field(&mut payload, record.file_id.as_bytes());
    payload.push(match record.coverage {
        Coverage::Full => 2,
        Coverage::Partial => 1,
        Coverage::None => 0,
    });
    payload.extend_from_slice(&record.expires_at.to_be_bytes());
    payload
}

fn append_field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

fn mac_hex(key: &[u8; 32], payload: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(&mac_bytes(key, payload))
}

fn mac_bytes(key: &[u8; 32], payload: &[u8]) -> [u8; 32] {
    const BLOCK_BYTES: usize = 64;
    let mut inner_key = [0x36u8; BLOCK_BYTES];
    let mut outer_key = [0x5cu8; BLOCK_BYTES];
    for index in 0..key.len() {
        inner_key[index] ^= key[index];
        outer_key[index] ^= key[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_key);
    inner.update(payload);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_key);
    outer.update(inner_digest);
    let result: [u8; 32] = outer.finalize().into();
    inner_key.zeroize();
    outer_key.zeroize();
    result
}

fn constant_time_eq(expected: &[u8], supplied: &[u8]) -> bool {
    if expected.len() != supplied.len() {
        return false;
    }
    expected
        .iter()
        .zip(supplied)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn digest_hex(value: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(&Sha256::digest(value))
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn load_or_create_attestation_key(path: &Path) -> Result<[u8; 32], String> {
    if !path.exists() {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key)
            .map_err(|error| format!("could not generate file attestation key: {error}"))?;
        let temporary = private_temporary_path(path, "key");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&temporary) {
            Ok(mut file) => {
                if let Err(error) = file.write_all(&key).and_then(|_| file.sync_all()) {
                    drop(file);
                    let _ = fs::remove_file(&temporary);
                    key.zeroize();
                    return Err(format!("could not write file attestation key: {error}"));
                }
                drop(file);
                if let Err(error) = restrict_private_file(&temporary) {
                    let _ = fs::remove_file(&temporary);
                    key.zeroize();
                    return Err(error);
                }
                match fs::hard_link(&temporary, path) {
                    Ok(()) => {
                        let _ = fs::remove_file(&temporary);
                        if let Err(error) =
                            sync_parent_directory(path).and_then(|_| restrict_private_file(path))
                        {
                            let _ = fs::remove_file(path);
                            key.zeroize();
                            return Err(error);
                        }
                        return Ok(key);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        let _ = fs::remove_file(&temporary);
                        key.zeroize();
                    }
                    Err(error) => {
                        let _ = fs::remove_file(&temporary);
                        key.zeroize();
                        return Err(format!("could not publish file attestation key: {error}"));
                    }
                }
            }
            Err(error) => {
                key.zeroize();
                return Err(format!(
                    "could not create temporary attestation key: {error}"
                ));
            }
        }
    }
    restrict_private_file(path)?;
    let bytes =
        fs::read(path).map_err(|error| format!("could not read file attestation key: {error}"))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        format!(
            "file attestation key must contain exactly 32 bytes (found {})",
            bytes.len()
        )
    })
}

fn atomic_private_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let temporary = private_temporary_path(path, "record");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("could not create file attestation: {error}"))?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_data()) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("could not write file attestation: {error}"));
    }
    drop(file);
    if let Err(error) = restrict_private_file(&temporary) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = replace_private_file(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    sync_parent_directory(path)
}

fn private_temporary_path(path: &Path, label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    path.with_extension(format!(
        "{label}.tmp-{}-{}-{sequence}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ))
}

#[cfg(windows)]
fn replace_private_file(temporary: &Path, path: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let from = temporary
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let to = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: both paths are NUL-terminated UTF-16 buffers that remain valid
    // for the duration of the call.
    let moved = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        return Err(format!(
            "could not atomically publish file attestation: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace_private_file(temporary: &Path, path: &Path) -> Result<(), String> {
    fs::rename(temporary, path)
        .map_err(|error| format!("could not atomically publish file attestation: {error}"))
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "file attestation path has no parent".to_string())?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("could not sync file attestation directory: {error}"))
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("could not restrict file attestation directory: {error}"))
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(path)
        .map_err(|error| format!("could not create file attestation directory: {error}"))?;
    restrict_directory(path)
}

#[cfg(windows)]
fn restrict_directory(path: &Path) -> Result<(), String> {
    restrict_windows_path(path, true)
}

#[cfg(windows)]
fn create_private_directory(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|error| format!("could not create file attestation directory: {error}"))?;
    restrict_directory(path)
}

#[cfg(not(any(unix, windows)))]
fn restrict_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn create_private_directory(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|error| format!("could not create file attestation directory: {error}"))
}

#[cfg(unix)]
fn restrict_private_file(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("could not restrict file attestation: {error}"))
}

#[cfg(windows)]
fn restrict_private_file(path: &Path) -> Result<(), String> {
    restrict_windows_path(path, false)
}

#[cfg(not(any(unix, windows)))]
fn restrict_private_file(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
fn restrict_windows_path(path: &Path, directory: bool) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{
        SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE,
        SET_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE, PROTECTED_DACL_SECURITY_INFORMATION,
        SUB_CONTAINERS_AND_OBJECTS_INHERIT,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

    let sid = current_process_sid()?;
    let trustee = TRUSTEE_W {
        pMultipleTrustee: std::ptr::null_mut(),
        MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_USER,
        ptstrName: sid.as_ptr().cast_mut().cast(),
    };
    let access = EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_ALL_ACCESS,
        grfAccessMode: SET_ACCESS,
        grfInheritance: if directory {
            SUB_CONTAINERS_AND_OBJECTS_INHERIT
        } else {
            NO_INHERITANCE
        },
        Trustee: trustee,
    };
    let mut acl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `access` and `acl` are valid for the duration of the call; the
    // returned ACL is owned by LocalAlloc and released below with LocalFree.
    let acl_status = unsafe { SetEntriesInAclW(1, &access, std::ptr::null(), &mut acl) };
    if acl_status != ERROR_SUCCESS || acl.is_null() {
        return Err("could not restrict file attestation ACL".to_string());
    }
    let mut wide_path = path.as_os_str().encode_wide().collect::<Vec<_>>();
    wide_path.push(0);
    // SAFETY: the path is NUL-terminated, `acl` is a valid ACL allocated by
    // SetEntriesInAclW, and all other optional security components are null.
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide_path.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl,
            std::ptr::null(),
        )
    };
    // SAFETY: `acl` came from SetEntriesInAclW and is released exactly once.
    unsafe { LocalFree(acl.cast()) };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err("could not restrict file attestation ACL".to_string())
    }
}

#[cfg(windows)]
fn current_process_sid() -> Result<&'static [u8], String> {
    use std::sync::OnceLock;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        CopySid, GetLengthSid, GetTokenInformation, IsValidSid, TokenUser, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    static SID: OnceLock<Result<Vec<u8>, String>> = OnceLock::new();
    SID.get_or_init(|| {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: `token` is a valid output pointer and the pseudo process
        // handle returned by GetCurrentProcess is valid in this process.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err("could not open Windows process token for attestation ACL".to_string());
        }
        let result = (|| {
            let mut required = 0_u32;
            // SAFETY: a null buffer with length zero is the documented size
            // query for GetTokenInformation.
            unsafe {
                GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut required)
            };
            if required < std::mem::size_of::<TOKEN_USER>() as u32 {
                return Err("could not size Windows process SID".to_string());
            }
            let mut token_user = vec![0_u8; required as usize];
            // SAFETY: `token_user` has the exact capacity requested above.
            if unsafe {
                GetTokenInformation(
                    token,
                    TokenUser,
                    token_user.as_mut_ptr().cast(),
                    required,
                    &mut required,
                )
            } == 0
            {
                return Err("could not read Windows process SID".to_string());
            }
            // SAFETY: a successful TokenUser query starts with TOKEN_USER.
            let source = unsafe { (*(token_user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
            if source.is_null() || unsafe { IsValidSid(source) } == 0 {
                return Err("Windows process SID is invalid".to_string());
            }
            // SAFETY: IsValidSid succeeded for `source`.
            let length = unsafe { GetLengthSid(source) };
            let mut sid = vec![0_u8; length as usize];
            // SAFETY: `sid` has `length` bytes and `source` is a valid SID.
            if unsafe { CopySid(length, sid.as_mut_ptr().cast(), source) } == 0 {
                return Err("could not copy Windows process SID".to_string());
            }
            Ok(sid)
        })();
        // SAFETY: OpenProcessToken returned this owned handle.
        unsafe { CloseHandle(token) };
        result
    })
    .as_deref()
    .map_err(Clone::clone)
}

pub(crate) fn remember_file_coverage(
    files: &mut HashMap<String, Coverage>,
    id: String,
    coverage: Coverage,
) {
    if !files.contains_key(&id) && files.len() >= MAX_TRACKED_FILE_IDS {
        if let Some(expired) = files.keys().next().cloned() {
            files.remove(&expired);
        }
    }
    files.insert(id, coverage);
}

fn scoped_registry_key(account_scope: &str, id: &str) -> String {
    format!("{account_scope}:{id}")
}

pub(crate) fn remember_scoped_file_coverage(
    files: &mut HashMap<String, Coverage>,
    account_scope: &str,
    id: String,
    coverage: Coverage,
) {
    remember_file_coverage(files, scoped_registry_key(account_scope, &id), coverage);
}

pub(crate) fn scoped_file_coverage(
    files: &HashMap<String, Coverage>,
    account_scope: &str,
    id: &str,
) -> Option<Coverage> {
    files.get(&scoped_registry_key(account_scope, id)).copied()
}

pub(crate) fn scoped_file_coverages(
    files: &HashMap<String, Coverage>,
    account_scope: &str,
) -> HashMap<String, Coverage> {
    let prefix = format!("{account_scope}:");
    files
        .iter()
        .filter_map(|(key, coverage)| {
            key.strip_prefix(&prefix)
                .map(|id| (id.to_string(), *coverage))
        })
        .collect()
}

pub(crate) fn supported_text_file(filename: &str, media_type: Option<&str>) -> bool {
    if media_type.is_some_and(|value| {
        let value = value.to_ascii_lowercase();
        value.starts_with("text/")
            || matches!(
                value.as_str(),
                "application/json"
                    | "application/jsonl"
                    | "application/javascript"
                    | "application/typescript"
                    | "application/x-ndjson"
                    | "application/toml"
                    | "application/xml"
                    | "application/yaml"
                    | "application/x-yaml"
            )
    }) {
        return true;
    }
    let path = Path::new(filename);
    if path
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|name| {
            matches!(
                name.to_ascii_lowercase().as_str(),
                "dockerfile"
                    | "makefile"
                    | "justfile"
                    | "procfile"
                    | "gemfile"
                    | "rakefile"
                    | ".gitignore"
                    | ".dockerignore"
                    | ".editorconfig"
                    | ".npmrc"
                    | ".yarnrc"
                    | ".prettierrc"
                    | ".eslintrc"
            )
        })
    {
        return true;
    }
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "txt"
                    | "md"
                    | "markdown"
                    | "csv"
                    | "tsv"
                    | "json"
                    | "jsonl"
                    | "ndjson"
                    | "xml"
                    | "yaml"
                    | "yml"
                    | "env"
                    | "log"
                    | "py"
                    | "pyi"
                    | "js"
                    | "mjs"
                    | "cjs"
                    | "jsx"
                    | "ts"
                    | "mts"
                    | "cts"
                    | "tsx"
                    | "rs"
                    | "go"
                    | "java"
                    | "kt"
                    | "kts"
                    | "c"
                    | "h"
                    | "cc"
                    | "cpp"
                    | "cxx"
                    | "hh"
                    | "hpp"
                    | "hxx"
                    | "cs"
                    | "swift"
                    | "scala"
                    | "sh"
                    | "bash"
                    | "zsh"
                    | "fish"
                    | "ps1"
                    | "psm1"
                    | "bat"
                    | "cmd"
                    | "toml"
                    | "ini"
                    | "cfg"
                    | "conf"
                    | "properties"
                    | "sql"
                    | "rb"
                    | "php"
                    | "pl"
                    | "pm"
                    | "lua"
                    | "r"
                    | "vue"
                    | "svelte"
                    | "astro"
                    | "css"
                    | "scss"
                    | "sass"
                    | "less"
                    | "html"
                    | "htm"
                    | "graphql"
                    | "gql"
                    | "proto"
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SCOPE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn temporary_attestation_directory(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "pentect-attestation-test-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn parses_quoted_boundary() {
        assert_eq!(
            multipart_boundary("multipart/form-data; boundary=\"hello-world\""),
            Some("hello-world".to_string())
        );
    }

    #[test]
    fn collects_only_known_anthropic_inline_media_blocks() {
        let value = serde_json::json!({
            "messages": [{"content": [
                {"type": "document", "source": {
                    "type": "base64",
                    "media_type": "application/pdf",
                    "data": "aGVsbG8="
                }},
                {"type": "image", "name": "screen.png", "source": {
                    "type": "base64",
                    "media_type": "image/png",
                    "data": "YWJjZA=="
                }},
                {"type": "document", "file_name": "notes.txt",
                    "media_type": "text/plain", "file_data": "YWJj"
                },
                {"type": "image", "image_url": "https://example.com/not-inline.png"},
                {"type": "tool_use", "input": {"type": "document", "source": {
                    "type": "base64", "data": "aGlkZGVu"
                }}}
            ]}]
        });
        let mut files = Vec::new();
        collect_anthropic_inline_files(&value, &mut files);
        assert_eq!(
            files,
            [
                InlineFileMetadata {
                    filename: None,
                    media_type: "application/pdf".to_string(),
                    size: 5,
                },
                InlineFileMetadata {
                    filename: Some("screen.png".to_string()),
                    media_type: "image/png".to_string(),
                    size: 4,
                },
                InlineFileMetadata {
                    filename: Some("notes.txt".to_string()),
                    media_type: "text/plain".to_string(),
                    size: 3,
                },
            ]
        );
    }

    #[test]
    fn collects_google_inline_data_but_not_function_arguments() {
        let value = serde_json::json!({
            "contents": [{"parts": [
                {"inlineData": {
                    "mimeType": "text/plain",
                    "data": "aGVsbG8="
                }},
                {"functionCall": {"args": {"inlineData": {
                    "mimeType": "text/plain",
                    "data": "aGlkZGVu"
                }}}}
            ]}]
        });
        let mut files = Vec::new();
        collect_google_inline_files(&value, &mut files);
        assert_eq!(
            files,
            [InlineFileMetadata {
                filename: None,
                media_type: "text/plain".to_string(),
                size: 5,
            }]
        );
    }

    #[test]
    fn recognizes_text_files_without_trusting_only_content_type() {
        assert!(supported_text_file("secrets.env", None));
        assert!(supported_text_file("payload.bin", Some("application/json")));
        for filename in [
            "main.py",
            "lib.rs",
            "app.tsx",
            "main.go",
            "build.ps1",
            "Cargo.toml",
            "schema.sql",
            "Dockerfile",
            ".gitignore",
        ] {
            assert!(
                supported_text_file(filename, Some("application/octet-stream")),
                "{filename}"
            );
        }
        assert!(!supported_text_file("report.pdf", Some("application/pdf")));
        assert!(supported_image_file("photo.jpg", None));
        assert!(supported_image_file("upload.bin", Some("image/png")));
        assert!(!supported_image_file("report.pdf", Some("application/pdf")));
    }

    #[test]
    fn rewrites_image_content_type_after_safe_regeneration() {
        let headers = b"Content-Disposition: form-data; name=\"file\"; filename=\"photo.jpg\"\r\nContent-Type: image/jpeg";
        let rewritten = headers_with_media_type(headers, "image/png").unwrap();
        let rewritten = std::str::from_utf8(&rewritten).unwrap();
        assert!(rewritten.contains("Content-Type: image/png"));
        assert!(!rewritten.contains("Content-Type: image/jpeg"));
    }

    #[test]
    fn multipart_parser_blocks_an_unavailable_masker_upload() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let body = Bytes::from_static(
            b"--boundary\r\nContent-Disposition: form-data; name=\"purpose\"\r\n\r\nuser_data\r\n--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"notes.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--boundary--\r\n",
        );
        let mut masker = pentect_agent::ActiveToolOutputMasker::new().unwrap();
        let error =
            protect_multipart_upload("multipart/form-data; boundary=boundary", &body, &mut masker)
                .err()
                .unwrap();
        assert!(error.contains("inspection is unavailable"), "{error}");
        assert_eq!(
            multipart_field(&body, b"--boundary", b"\r\n--boundary", "purpose").as_deref(),
            Some("user_data")
        );
    }

    #[test]
    fn persistent_attestation_is_bound_to_provider_upstream_and_file() {
        let root = temporary_attestation_directory("binding");
        let store = FileAttestationStore::open(&root).unwrap();
        store
            .remember(
                "openai",
                "https://api.example.test/v1",
                TEST_SCOPE,
                "file-123",
                Coverage::Full,
            )
            .unwrap();
        drop(store);

        let reopened = FileAttestationStore::open(&root).unwrap();
        assert_eq!(
            reopened
                .coverage(
                    "openai",
                    "https://api.example.test/v1",
                    TEST_SCOPE,
                    "file-123"
                )
                .unwrap(),
            Some(Coverage::Full)
        );
        assert_eq!(
            reopened
                .coverage(
                    "anthropic",
                    "https://api.example.test/v1",
                    TEST_SCOPE,
                    "file-123"
                )
                .unwrap(),
            None
        );
        assert_eq!(
            reopened
                .coverage(
                    "openai",
                    "https://other.example.test/v1",
                    TEST_SCOPE,
                    "file-123"
                )
                .unwrap(),
            None
        );
        assert_eq!(
            reopened
                .coverage(
                    "openai",
                    "https://api.example.test/v1",
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "file-123",
                )
                .unwrap(),
            None
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn uploaded_file_attestations_rehydrate_openai_and_anthropic_references() {
        let root = temporary_attestation_directory("providers");
        let store = FileAttestationStore::open(&root).unwrap();
        store
            .remember(
                "openai",
                "https://api.openai.test/v1",
                TEST_SCOPE,
                "file-openai",
                Coverage::Full,
            )
            .unwrap();
        store
            .remember(
                "anthropic",
                "https://api.anthropic.test",
                TEST_SCOPE,
                "file-anthropic",
                Coverage::Partial,
            )
            .unwrap();

        let openai = store
            .coverages_in_json(
                br#"{"input":[{"type":"input_file","file_id":"file-openai"}]}"#,
                "openai",
                "https://api.openai.test/v1",
                TEST_SCOPE,
            )
            .unwrap();
        assert_eq!(openai, vec![("file-openai".to_string(), Coverage::Full)]);

        let anthropic = store
            .coverages_in_json(
                br#"{"messages":[{"content":[{"type":"document","source":{"type":"file","file_id":"file-anthropic"}}]}]}"#,
                "anthropic",
                "https://api.anthropic.test",
                TEST_SCOPE,
            )
            .unwrap();
        assert_eq!(
            anthropic,
            vec![("file-anthropic".to_string(), Coverage::Partial)]
        );
        assert!(store
            .coverages_in_json(
                br#"{"file_id":"file-openai"}"#,
                "anthropic",
                "https://api.openai.test/v1",
                TEST_SCOPE,
            )
            .unwrap()
            .is_empty());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn tampered_or_expired_attestation_is_not_trusted() {
        let root = temporary_attestation_directory("tamper");
        let store = FileAttestationStore::open(&root).unwrap();
        store
            .remember_for(
                "openai",
                "https://api.example.test/v1",
                TEST_SCOPE,
                "file-expired",
                Coverage::Full,
                Duration::ZERO,
            )
            .unwrap();
        let expired_path = store.record_path(
            "openai",
            "https://api.example.test/v1",
            TEST_SCOPE,
            "file-expired",
        );
        let mut expired: FileAttestation =
            serde_json::from_slice(&fs::read(&expired_path).unwrap()).unwrap();
        expired.expires_at = 0;
        expired.mac = mac_hex(&store.key, &attestation_payload(&expired));
        fs::write(&expired_path, serde_json::to_vec(&expired).unwrap()).unwrap();
        assert_eq!(
            store
                .coverage(
                    "openai",
                    "https://api.example.test/v1",
                    TEST_SCOPE,
                    "file-expired"
                )
                .unwrap(),
            None
        );

        store
            .remember(
                "openai",
                "https://api.example.test/v1",
                TEST_SCOPE,
                "file-tampered",
                Coverage::Full,
            )
            .unwrap();
        let tampered_path = store.record_path(
            "openai",
            "https://api.example.test/v1",
            TEST_SCOPE,
            "file-tampered",
        );
        let mut tampered: FileAttestation =
            serde_json::from_slice(&fs::read(&tampered_path).unwrap()).unwrap();
        tampered.account_scope =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
        fs::write(&tampered_path, serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert_eq!(
            store
                .coverage(
                    "openai",
                    "https://api.example.test/v1",
                    TEST_SCOPE,
                    "file-tampered"
                )
                .unwrap(),
            None
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn oversized_attestation_record_is_rejected_without_unbounded_read() {
        let root = temporary_attestation_directory("oversized");
        let store = FileAttestationStore::open(&root).unwrap();
        store
            .remember(
                "openai",
                "https://api.example.test/v1",
                TEST_SCOPE,
                "file-large",
                Coverage::Full,
            )
            .unwrap();
        let path = store.record_path(
            "openai",
            "https://api.example.test/v1",
            TEST_SCOPE,
            "file-large",
        );
        fs::write(&path, vec![b'x'; MAX_ATTESTATION_RECORD_BYTES + 1]).unwrap();
        assert_eq!(
            store
                .coverage(
                    "openai",
                    "https://api.example.test/v1",
                    TEST_SCOPE,
                    "file-large",
                )
                .unwrap(),
            None
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn multipart_request_size_is_bounded_before_parsing() {
        let body = Bytes::from(vec![0u8; MAX_MULTIPART_BYTES + 1]);
        let mut masker = pentect_agent::ActiveToolOutputMasker::new().unwrap();
        let error =
            protect_multipart_upload("multipart/form-data; boundary=boundary", &body, &mut masker)
                .err()
                .unwrap();
        assert!(error.contains("too large"));
    }
}
