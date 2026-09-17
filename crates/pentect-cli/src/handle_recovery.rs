//! Provider-independent, bounded recovery of rejected model tool proposals.
//! Only already-protected request bytes are retained. Rejected response bytes
//! are never appended to model history or delivered to a client.
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full};
use hyper::body::Bytes;
use hyper::Response;
use serde_json::{json, Value};
use std::{error::Error, future::Future};

type Body = UnsyncBoxBody<Bytes, Box<dyn Error + Send + Sync>>;
const LIMIT: usize = 32 * 1024 * 1024;
const ATTEMPTS: usize = 2;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Dialect {
    Responses,
    Chat,
    Gemini,
    CloudCode,
}

pub(crate) fn feedback(body: &[u8], dialect: Dialect, error: &str) -> Result<Bytes, String> {
    let mut value: Value =
        serde_json::from_slice(body).map_err(|_| "invalid protected recovery request")?;
    let notice = crate::claude_http_proxy::recovery_notice(error);
    let root = match dialect {
        Dialect::CloudCode => value
            .get_mut("request")
            .ok_or("missing protected Cloud Code request")?,
        _ => &mut value,
    };
    match dialect {
        Dialect::Responses => {
            let input = root.get_mut("input").ok_or("missing protected input")?;
            if let Some(text) = input.as_str() {
                *input = json!([{"role":"user","content":text}]);
            }
            input
                .as_array_mut()
                .ok_or("invalid protected input")?
                .push(json!({"role":"user","content":notice}));
        }
        Dialect::Chat => root
            .get_mut("messages")
            .and_then(Value::as_array_mut)
            .ok_or("missing protected messages")?
            .push(json!({"role":"user","content":notice})),
        Dialect::Gemini | Dialect::CloudCode => {
            root.get_mut("contents")
                .and_then(Value::as_array_mut)
                .ok_or("missing protected contents")?
                .push(json!({"role":"user","parts":[{"text":notice}]}));
            if let Some(config) = root
                .pointer_mut("/toolConfig/functionCallingConfig")
                .and_then(Value::as_object_mut)
            {
                if config.get("mode").and_then(Value::as_str) != Some("NONE") {
                    config.insert("mode".into(), json!("AUTO"));
                    config.remove("allowedFunctionNames");
                }
            }
        }
    }
    if let Some(object) = root.as_object_mut() {
        if object.get("tool_choice").and_then(Value::as_str) != Some("none") {
            object.remove("tool_choice");
        }
    }
    serde_json::to_vec(&value)
        .map(Bytes::from)
        .map_err(|_| "could not encode protected recovery request".into())
}

fn full(bytes: Bytes) -> Body {
    Full::new(bytes)
        .map_err(|never| match never {})
        .boxed_unsync()
}

pub(crate) async fn collect(mut body: Body) -> Result<Bytes, String> {
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| e.to_string())?;
        if let Ok(chunk) = frame.into_data() {
            if bytes.len().saturating_add(chunk.len()) > LIMIT {
                return Err("protected response exceeded limit".into());
            }
            bytes.extend_from_slice(&chunk);
        }
    }
    Ok(Bytes::from(bytes))
}

fn stopped(dialect: Dialect, streaming: bool, error: &str) -> Response<Body> {
    let text = format!(
        "{} Automatic recovery stopped. No rejected tool was executed.",
        crate::claude_http_proxy::recovery_notice(error)
    );
    let value = match dialect {
        Dialect::Responses => {
            json!({"id":"resp_pentect_recovery","object":"response","created_at":0,"status":"completed","error":null,"incomplete_details":null,"model":"pentect-local","output":[{"id":"msg_pentect_recovery","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":text,"annotations":[]}]}],"usage":{"input_tokens":0,"output_tokens":0,"total_tokens":0}})
        }
        Dialect::Chat => {
            json!({"id":"chatcmpl_pentect_recovery","object":"chat.completion","created":0,"model":"pentect-local","choices":[{"index":0,"message":{"role":"assistant","content":text},"finish_reason":"stop"}]})
        }
        Dialect::Gemini | Dialect::CloudCode => {
            let response = json!({"candidates":[{"index":0,"content":{"role":"model","parts":[{"text":text}]},"finishReason":"STOP"}]});
            if matches!(dialect, Dialect::CloudCode) {
                json!({"response":response})
            } else {
                response
            }
        }
    };
    let body = if !streaming {
        value.to_string()
    } else {
        match dialect {
            Dialect::Responses => {
                let mut start = value.clone();
                start["status"] = json!("in_progress");
                start["output"] = json!([]);
                let events = [
                    json!({"type":"response.created","response":start}),
                    json!({"type":"response.output_item.added","output_index":0,"item":{"id":"msg_pentect_recovery","type":"message","role":"assistant","status":"in_progress","content":[]}}),
                    json!({"type":"response.content_part.added","item_id":"msg_pentect_recovery","output_index":0,"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}}),
                    json!({"type":"response.output_text.delta","item_id":"msg_pentect_recovery","output_index":0,"content_index":0,"delta":text}),
                    json!({"type":"response.output_text.done","item_id":"msg_pentect_recovery","output_index":0,"content_index":0,"text":text}),
                    json!({"type":"response.content_part.done","item_id":"msg_pentect_recovery","output_index":0,"content_index":0,"part":value["output"][0]["content"][0]}),
                    json!({"type":"response.output_item.done","output_index":0,"item":value["output"][0]}),
                    json!({"type":"response.completed","response":value}),
                ];
                events
                    .into_iter()
                    .enumerate()
                    .map(|(i, mut e)| {
                        e["sequence_number"] = json!(i);
                        format!("event: {}\ndata: {e}\n\n", e["type"].as_str().unwrap())
                    })
                    .collect()
            }
            Dialect::Chat => {
                let chunk = json!({"id":"chatcmpl_pentect_recovery","object":"chat.completion.chunk","created":0,"model":"pentect-local","choices":[{"index":0,"delta":{"role":"assistant","content":text},"finish_reason":"stop"}]});
                format!("data: {chunk}\n\ndata: [DONE]\n\n")
            }
            _ => format!("data: {value}\n\n"),
        }
    };
    Response::builder()
        .header(
            "content-type",
            if streaming {
                "text/event-stream"
            } else {
                "application/json"
            },
        )
        .body(full(Bytes::from(body)))
        .expect("static recovery response")
}

pub(crate) async fn run<F, Fut>(
    template: reqwest::RequestBuilder,
    original: Bytes,
    dialect: Dialect,
    streaming: bool,
    surface: &'static str,
    coverage: &'static str,
    mut validate: F,
) -> Result<Response<Body>, String>
where
    F: FnMut(reqwest::Response, bool) -> Fut + Send,
    Fut: Future<Output = Result<Bytes, String>> + Send,
{
    let mut body = original.clone();
    for attempt in 0..=ATTEMPTS {
        let response = template
            .try_clone()
            .ok_or("protected request cannot be cloned")?
            .body(body.clone())
            .send()
            .await
            .map_err(|_| "protected upstream request failed")?;
        let status = response.status();
        let headers = response.headers().clone();
        let context = crate::gateway_diagnostics::RequestContext {
            endpoint: match dialect {
                Dialect::Responses => "responses",
                Dialect::Chat => "chat-completions",
                _ if streaming => "stream-generate-content",
                _ => "generate-content",
            },
            method: "POST",
        };
        crate::gateway_diagnostics::record_upstream_status(surface, context, status);
        if headers
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| !v.eq_ignore_ascii_case("identity"))
        {
            return Err("protected upstream returned unsupported content encoding".into());
        }
        let event_stream = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                v.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("text/event-stream")
            })
            .unwrap_or(streaming);
        let result = if status.is_success() {
            validate(response, event_stream).await
        } else {
            let stream = response.bytes_stream();
            use futures_util::StreamExt;
            let framed = stream.map(|r| {
                r.map(hyper::body::Frame::data)
                    .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)
            });
            collect(http_body_util::StreamBody::new(framed).boxed_unsync()).await
        };
        match result {
            Ok(bytes) => {
                if attempt > 0 && status.is_success() {
                    crate::gateway_diagnostics::record(
                        surface,
                        "handle-recovery-completed",
                        "validated",
                        context,
                        None,
                        false,
                    );
                }
                let mut builder = Response::builder().status(status);
                for (name, value) in &headers {
                    let named = headers
                        .get_all("connection")
                        .iter()
                        .filter_map(|v| v.to_str().ok())
                        .flat_map(|v| v.split(','))
                        .any(|v| v.trim().eq_ignore_ascii_case(name.as_str()));
                    if !named
                        && !name.as_str().starts_with("x-pentect-")
                        && !matches!(
                            name.as_str(),
                            "content-length"
                                | "content-encoding"
                                | "transfer-encoding"
                                | "connection"
                                | "keep-alive"
                                | "trailer"
                                | "upgrade"
                                | "proxy-authenticate"
                                | "proxy-authorization"
                                | "te"
                                | "etag"
                                | "content-md5"
                                | "digest"
                        )
                    {
                        builder = builder.header(name, value);
                    }
                }
                return builder
                    .header("x-pentect-coverage", coverage)
                    .body(full(bytes))
                    .map_err(|_| "could not build recovery response".into());
            }
            Err(error) => {
                let kind = crate::claude_http_proxy::sse_tool_rejection_kind(&error);
                crate::gateway_diagnostics::record(
                    surface,
                    "tool-input-rejected",
                    kind,
                    context,
                    None,
                    false,
                );
                if error.starts_with("protected handle use is unsupported") {
                    return Ok(stopped(dialect, streaming, &error));
                }
                if !crate::claude_http_proxy::recoverable_handle_failure(&error) {
                    return Err(error);
                }
                if attempt == ATTEMPTS {
                    crate::gateway_diagnostics::record(
                        surface,
                        "handle-recovery-exhausted",
                        kind,
                        context,
                        None,
                        false,
                    );
                    return Ok(stopped(dialect, streaming, &error));
                }
                crate::gateway_diagnostics::record(
                    surface,
                    if attempt == 0 {
                        "handle-recovery-attempt-1"
                    } else {
                        "handle-recovery-attempt-2"
                    },
                    kind,
                    context,
                    None,
                    false,
                );
                body = feedback(&original, dialect, &error)?;
            }
        }
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(dialect: Dialect) -> Value {
        match dialect {
            Dialect::Responses => {
                json!({"input":"protected history","previous_response_id":"previous","tool_choice":"required"})
            }
            Dialect::Chat => {
                json!({"messages":[{"role":"user","content":"protected history"}],"tool_choice":"required"})
            }
            Dialect::Gemini => {
                json!({"contents":[{"role":"user","parts":[{"text":"protected history"}]}],"toolConfig":{"functionCallingConfig":{"mode":"ANY","allowedFunctionNames":["Bash"]}}})
            }
            Dialect::CloudCode => json!({"project":"project","request":request(Dialect::Gemini)}),
        }
    }

    #[test]
    fn all_dialects_preserve_history_and_use_only_fixed_feedback() {
        for dialect in [
            Dialect::Responses,
            Dialect::Chat,
            Dialect::Gemini,
            Dialect::CloudCode,
        ] {
            for error in [
                "protected handle view is malformed secret-detail",
                "protected handle view is unsupported secret-detail",
                "protected handle is unavailable in this session secret-detail",
            ] {
                let original = request(dialect);
                let bytes =
                    feedback(&serde_json::to_vec(&original).unwrap(), dialect, error).unwrap();
                let text = String::from_utf8(bytes.to_vec()).unwrap();
                assert!(!text.contains("secret-detail"));
                assert!(text.contains("protected history"));
                assert!(text.contains("none of its client tools ran"));
                assert!(!text.contains("required"));
                let updated: Value = serde_json::from_slice(&bytes).unwrap();
                match dialect {
                    Dialect::Responses => assert_eq!(
                        updated["previous_response_id"],
                        original["previous_response_id"]
                    ),
                    Dialect::Chat => assert_eq!(updated["messages"][0], original["messages"][0]),
                    Dialect::Gemini => {
                        assert_eq!(updated["contents"][0], original["contents"][0]);
                        assert_eq!(
                            updated["toolConfig"]["functionCallingConfig"]["mode"],
                            "AUTO"
                        );
                    }
                    Dialect::CloudCode => assert_eq!(updated["project"], original["project"]),
                }
            }
        }
    }

    #[tokio::test]
    async fn stopped_responses_are_native_and_contain_no_tool_or_error_event() {
        for dialect in [
            Dialect::Responses,
            Dialect::Chat,
            Dialect::Gemini,
            Dialect::CloudCode,
        ] {
            for streaming in [false, true] {
                let response = stopped(
                    dialect,
                    streaming,
                    "protected handle view is malformed secret-detail",
                );
                assert_eq!(response.status(), 200);
                let body = String::from_utf8(collect(response.into_body()).await.unwrap().to_vec())
                    .unwrap();
                assert!(body.contains("Automatic recovery stopped"));
                assert!(!body.contains("secret-detail"));
                assert!(!body.contains("event: error"));
                assert!(!body.contains("function_call"));
                if !streaming {
                    serde_json::from_str::<Value>(&body).unwrap();
                }
            }
        }
    }

    #[tokio::test]
    async fn all_dialects_retry_only_protected_history_and_stop_at_bound() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for dialect in [
            Dialect::Responses,
            Dialect::Chat,
            Dialect::Gemini,
            Dialect::CloudCode,
        ] {
            for exhaust in [false, true] {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let upstream = tokio::spawn(async move {
                    for attempt in 0..if exhaust { 3 } else { 2 } {
                        let (mut socket, _) = listener.accept().await.unwrap();
                        let mut bytes = Vec::new();
                        loop {
                            let mut buf = [0; 4096];
                            let n = socket.read(&mut buf).await.unwrap();
                            assert!(n > 0);
                            bytes.extend_from_slice(&buf[..n]);
                            if let Some(end) = bytes.windows(4).position(|s| s == b"\r\n\r\n") {
                                let headers = String::from_utf8_lossy(&bytes[..end]);
                                let len: usize = headers
                                    .lines()
                                    .find_map(|l| {
                                        l.to_ascii_lowercase()
                                            .strip_prefix("content-length:")
                                            .map(|s| s.trim().parse().unwrap())
                                    })
                                    .unwrap();
                                if bytes.len() >= end + 4 + len {
                                    break;
                                }
                            }
                        }
                        let text = String::from_utf8_lossy(&bytes);
                        assert!(text.contains("protected history"));
                        assert!(!text.contains("rejected-private-body"));
                        if attempt > 0 {
                            assert!(text.contains("Pentect could not restore"));
                        }
                        let body = if exhaust || attempt == 0 {
                            "rejected-private-body"
                        } else {
                            "validated"
                        };
                        socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
                    }
                });
                let result = run(
                    reqwest::Client::new().post(format!("http://{address}")),
                    Bytes::from(serde_json::to_vec(&request(dialect)).unwrap()),
                    dialect,
                    false,
                    "openai",
                    "full",
                    |response, _| async move {
                        let bytes = response.bytes().await.unwrap();
                        if bytes == "rejected-private-body" {
                            Err("protected handle view is malformed".into())
                        } else {
                            Ok(bytes)
                        }
                    },
                )
                .await
                .unwrap();
                let body = collect(result.into_body()).await.unwrap();
                assert!(!String::from_utf8_lossy(&body).contains("rejected-private-body"));
                if !exhaust {
                    assert_eq!(body, "validated");
                }
                upstream.await.unwrap();
            }
        }
    }
}
