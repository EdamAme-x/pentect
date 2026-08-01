//! File-upload protection shared by the HTTP gateways.
//!
//! Only UTF-8 text formats are rewritten here. Binary formats require a
//! format-aware rewriter; treating arbitrary bytes as text would corrupt them
//! while pretending they were protected.

use hyper::body::Bytes;
use memchr::memmem;
use std::collections::HashMap;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    let boundary = multipart_boundary(content_type)
        .ok_or_else(|| "Files API upload is missing a multipart boundary".to_string())?;
    let delimiter = format!("--{boundary}").into_bytes();
    let body_separator = b"\r\n\r\n";
    let mut next_part_prefix = Vec::with_capacity(delimiter.len() + 2);
    next_part_prefix.extend_from_slice(b"\r\n");
    next_part_prefix.extend_from_slice(&delimiter);
    let purpose = multipart_field(body, &delimiter, &next_part_prefix, "purpose");
    let immutable_dataset = purpose
        .as_deref()
        .is_some_and(|purpose| matches!(purpose, "batch" | "fine-tune" | "evals"));
    let mut cursor = 0;
    let mut output = Vec::with_capacity(body.len());
    let mut saw_file = false;
    let mut coverage = Coverage::Full;
    let mut plugin_partial = false;

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
        let content_start = headers_end + body_separator.len();
        let Some(content_relative_end) = memmem::find(&body[content_start..], &next_part_prefix)
        else {
            return Err("file upload blocked: unterminated multipart file".to_string());
        };
        let content_end = content_start + content_relative_end;
        let headers = &body[headers_start..headers_end];
        let content = &body[content_start..content_end];

        output.extend_from_slice(&body[cursor..content_start]);
        if let Some(file) = file_part(headers) {
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
                            output.extend_from_slice(final_masked.as_bytes());
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
            } else {
                return Err(
                    "file upload blocked: this binary format cannot be inspected safely"
                        .to_string(),
                );
            }
        } else {
            output.extend_from_slice(content);
        }
        cursor = content_end;
    }

    if cursor < body.len() {
        output.extend_from_slice(&body[cursor..]);
    }
    if !saw_file {
        coverage = Coverage::None;
    } else if plugin_partial {
        coverage = Coverage::Partial;
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
        filename,
        media_type: media_type.map(str::to_string),
    })
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

fn disposition_parameter(header: &str, expected: &str) -> Option<String> {
    header.split(';').skip(1).find_map(|parameter| {
        let (name, value) = parameter.trim().split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case(expected)
            .then(|| value.trim().trim_matches('"').to_string())
    })
}

const MAX_TRACKED_FILE_IDS: usize = 1024;

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

pub(crate) fn supported_text_file(filename: &str, media_type: Option<&str>) -> bool {
    if media_type.is_some_and(|value| {
        let value = value.to_ascii_lowercase();
        value.starts_with("text/")
            || matches!(
                value.as_str(),
                "application/json"
                    | "application/jsonl"
                    | "application/x-ndjson"
                    | "application/xml"
                    | "application/yaml"
                    | "application/x-yaml"
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
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quoted_boundary() {
        assert_eq!(
            multipart_boundary("multipart/form-data; boundary=\"hello-world\""),
            Some("hello-world".to_string())
        );
    }

    #[test]
    fn recognizes_text_files_without_trusting_only_content_type() {
        assert!(supported_text_file("secrets.env", None));
        assert!(supported_text_file("payload.bin", Some("application/json")));
        assert!(!supported_text_file("report.pdf", Some("application/pdf")));
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
}
