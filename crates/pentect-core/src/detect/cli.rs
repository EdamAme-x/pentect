use super::{shell, Detector};
use crate::model::*;
use crate::normalize::NormalizedView;

pub struct CliCredentialDetector;

impl Detector for CliCredentialDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let text = view.text();
        if !text.as_bytes().contains(&b'-')
            || !(shell::contains_ascii_ci(text, "password")
                || shell::contains_ascii_ci(text, "passwd")
                || shell::contains_ascii_ci(text, "pwd")
                || shell::contains_ascii_ci(text, "convertto-securestring"))
        {
            return Vec::new();
        }

        let mut out = Vec::new();
        let mut line_start = 0;
        for line in text.split_inclusive('\n') {
            inspect_line(
                view,
                &mut out,
                line_start,
                line.trim_end_matches(['\r', '\n']),
            );
            line_start += line.len();
        }
        if !text.ends_with('\n') && line_start < text.len() {
            inspect_line(view, &mut out, line_start, &text[line_start..]);
        }
        out
    }
}

fn inspect_line(view: &NormalizedView, out: &mut Vec<Span>, line_start: usize, line: &str) {
    if !shell::contains_ascii_ci(line, "-password")
        && !shell::contains_ascii_ci(line, "-passwd")
        && !shell::contains_ascii_ci(line, "-pwd")
        && !shell::contains_ascii_ci(line, "convertto-securestring")
    {
        return;
    }
    let tokens = shell::tokens(line, line_start);
    if tokens.is_empty() {
        return;
    }
    inspect_powershell_password_parameter(view, out, &tokens);
    inspect_convert_to_secure_string(view, out, &tokens);
}

fn inspect_powershell_password_parameter(
    view: &NormalizedView,
    out: &mut Vec<Span>,
    tokens: &[shell::Token],
) {
    let Some(command_index) = tokens
        .iter()
        .position(|token| is_powershell_command_name(&token.value))
    else {
        return;
    };

    let mut i = command_index + 1;
    while i < tokens.len() {
        let token = &tokens[i];
        if is_password_option(&token.value) {
            if let Some(next) = tokens.get(i + 1) {
                push_cli_password(view, out, next, 0);
            }
            i += 2;
            continue;
        }
        if let Some(value_start) = password_option_inline_value_start(&token.value) {
            push_cli_password(view, out, token, value_start);
        }
        i += 1;
    }
}

fn inspect_convert_to_secure_string(
    view: &NormalizedView,
    out: &mut Vec<Span>,
    tokens: &[shell::Token],
) {
    let Some(command_index) = tokens.iter().position(|token| {
        shell::basename(&token.value).eq_ignore_ascii_case("ConvertTo-SecureString")
    }) else {
        return;
    };
    if !tokens[command_index + 1..]
        .iter()
        .any(|token| token.value.eq_ignore_ascii_case("-AsPlainText"))
    {
        return;
    }
    let arguments = &tokens[command_index + 1..];
    let value = arguments
        .windows(2)
        .find(|pair| pair[0].value.eq_ignore_ascii_case("-String"))
        .map(|pair| &pair[1])
        .or_else(|| {
            arguments
                .iter()
                .find(|token| !token.value.is_empty() && !token.value.starts_with('-'))
        });
    let Some(value) = value else {
        return;
    };
    push_cli_password(view, out, value, 0);
}

fn is_powershell_command_name(value: &str) -> bool {
    let value = shell::basename(value);
    let Some((verb, noun)) = value.split_once('-') else {
        return false;
    };
    (2..=32).contains(&verb.len())
        && (2..=64).contains(&noun.len())
        && verb.bytes().all(|b| b.is_ascii_alphabetic())
        && noun
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn is_password_option(value: &str) -> bool {
    matches!(
        normalized_option_name(value).as_deref(),
        Some("password" | "passwd" | "pwd")
    )
}

fn password_option_inline_value_start(value: &str) -> Option<usize> {
    let (name, separator) = value.find([':', '=']).map(|pos| (&value[..pos], pos + 1))?;
    matches!(
        normalized_option_name(name).as_deref(),
        Some("password" | "passwd" | "pwd")
    )
    .then_some(separator)
}

fn normalized_option_name(value: &str) -> Option<String> {
    let name = value.trim_start_matches('-');
    (!name.is_empty()).then(|| name.to_ascii_lowercase())
}

fn push_cli_password(
    view: &NormalizedView,
    out: &mut Vec<Span>,
    token: &shell::Token,
    value_start: usize,
) {
    if value_start >= token.value.len() || value_start >= token.byte_to_raw.len() {
        return;
    }
    let value = token.value[value_start..].trim();
    if !cli_password_is_material(value) {
        return;
    }
    let trim_left =
        token.value[value_start..].len() - token.value[value_start..].trim_start().len();
    let trim_right = value.len();
    let start = value_start + trim_left;
    let end = start + trim_right;
    if start >= end {
        return;
    }
    out.push(Span {
        range: view.to_raw(ByteRange::new(
            token.byte_to_raw[start],
            token.byte_to_raw[end - 1] + 1,
        )),
        category: Category::Secret,
        label: labels::CMD_PASSWORD.to_string(),
        confidence: Confidence::High,
        source: DetectorId::Rule,
    });
}

fn cli_password_is_material(value: &str) -> bool {
    let value = value.trim();
    if !(6..=256).contains(&value.len()) {
        return false;
    }
    if value
        .bytes()
        .any(|b| matches!(b, b'<' | b'>' | b'{' | b'}' | b'*'))
    {
        return false;
    }
    let normalized = normalize_password_word(value);
    if matches!(
        normalized.as_str(),
        "password" | "passwd" | "pwd" | "secret" | "token" | "example" | "sample" | "value"
    ) {
        return false;
    }
    if value.starts_with('$') || value.starts_with('%') {
        return false;
    }
    let has_upper = value.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = value.bytes().any(|b| b.is_ascii_lowercase());
    let has_digit = value.bytes().any(|b| b.is_ascii_digit());
    let has_symbol = value
        .bytes()
        .any(|b| !b.is_ascii_alphanumeric() && !matches!(b, b'_' | b'-' | b'.' | b'@'))
        || value.contains('@');
    value.len() >= 7 || (has_symbol && (has_upper || has_lower)) || (has_digit && has_lower)
}

fn normalize_password_word(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::region;

    fn labels(raw: &str) -> Vec<(String, String)> {
        let reg = region(raw);
        let view = NormalizedView::build(&reg, raw);
        CliCredentialDetector
            .detect(&view)
            .into_iter()
            .map(|span| {
                (
                    span.label,
                    raw[span.range.start..span.range.end].to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn powershell_password_parameter_masks_value() {
        assert_eq!(
            labels("/// <code>$obj = Get-NtToken -Logon -User Bob -Password KnkL@sgadiw</code>"),
            [("CMD_PASSWORD".to_string(), "KnkL@sgadiw".to_string())]
        );
        assert_eq!(
            labels("$obj = Get-NtToken -Password:IaiA@eqhtlc -Domain BADGERS"),
            [("CMD_PASSWORD".to_string(), "IaiA@eqhtlc".to_string())]
        );
    }

    #[test]
    fn convert_to_secure_string_plaintext_masks_value() {
        assert_eq!(
            labels("$password = ConvertTo-SecureString 'xngveqs' -AsPlainText -Force;"),
            [("CMD_PASSWORD".to_string(), "xngveqs".to_string())]
        );
        assert_eq!(
            labels("$password = ConvertTo-SecureString -AsPlainText 'MySuperSecret123!' -Force;"),
            [("CMD_PASSWORD".to_string(), "MySuperSecret123!".to_string())]
        );
        assert_eq!(
            labels(
                "$password = ConvertTo-SecureString -Force -String '-starts-with-dash' -AsPlainText;"
            ),
            [
                (
                    "CMD_PASSWORD".to_string(),
                    "-starts-with-dash".to_string()
                )
            ]
        );
    }

    #[test]
    fn command_password_templates_are_ignored() {
        for raw in [
            "$obj = Get-NtToken -Password password",
            "$obj = Get-NtToken -Password $password",
            "svn --username 'foo' --password 'bar \\'bar' https://foo.example.org/svn/",
        ] {
            assert!(labels(raw).is_empty(), "{raw}: {:?}", labels(raw));
        }
    }
}
