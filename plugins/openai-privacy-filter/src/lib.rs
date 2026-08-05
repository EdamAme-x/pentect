use pentect_plugin::{Category, Confidence, Finding, HttpRequest, Inspect, PluginResult};
use serde::Deserialize;
use std::collections::BTreeMap;

const ENDPOINT: &str = "http://127.0.0.1:8787/v1/inspect";
const RESPONSE_CAPACITY: usize = 1024 * 1024;

#[derive(Deserialize)]
struct FilterResponse {
    schema: String,
    spans: Vec<FilterSpan>,
}

#[derive(Deserialize)]
struct FilterSpan {
    start: usize,
    end: usize,
    label: String,
}

fn inspect(context: &mut Inspect) -> PluginResult {
    if context.input().text.is_empty() {
        return Ok(());
    }

    let mut headers = BTreeMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let request = HttpRequest {
        method: "POST".to_string(),
        url: ENDPOINT.to_string(),
        headers,
        body: serde_json::to_string(&serde_json::json!({
            "text": context.input().text,
        }))?,
    };

    let response = match context.fetch(&request, RESPONSE_CAPACITY) {
        Ok(response) => response,
        Err(_) => {
            context.block("OpenAI Privacy Filter is not available on 127.0.0.1:8787");
            return Ok(());
        }
    };
    if response.error.is_some() || response.status != Some(200) {
        context.block("OpenAI Privacy Filter returned an error");
        return Ok(());
    }

    let response = match serde_json::from_str::<FilterResponse>(&response.body) {
        Ok(response) if response.schema == "pentect.openai-privacy-filter.v1" => response,
        _ => {
            context.block("OpenAI Privacy Filter returned an invalid response");
            return Ok(());
        }
    };

    for span in response.spans {
        let (label, category) = label(&span.label);
        context.add_finding(Finding {
            start: span.start,
            end: span.end,
            label,
            category: Some(category),
            confidence: Some(Confidence::Medium),
        })?;
    }
    Ok(())
}

fn label(value: &str) -> (String, Category) {
    let category = if value == "secret" {
        Category::Secret
    } else {
        Category::Pii
    };
    let label = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    let label = label.trim_matches('_').to_string();
    let label = if label.is_empty() {
        "PII".to_string()
    } else {
        label
    };
    (label, category)
}

pentect_plugin::export!(inspect);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_labels_become_handle_labels() {
        let (pii_label, pii_category) = label("private_email");
        assert_eq!(pii_label, "PRIVATE_EMAIL");
        assert!(matches!(pii_category, Category::Pii));

        let (secret_label, secret_category) = label("secret");
        assert_eq!(secret_label, "SECRET");
        assert!(matches!(secret_category, Category::Secret));
    }
}
