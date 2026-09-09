use super::{shell, structural, Detector};
use crate::model::*;
use crate::normalize::NormalizedView;

pub struct CliCredentialDetector;

impl Detector for CliCredentialDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let text = view.text();
        if !may_contain_cli_credential_boundary(text) {
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
    if !may_contain_cli_credential_boundary(line) {
        return;
    }
    let tokens = shell::tokens(line, line_start);
    for command in shell::command_slices(&tokens, view.text()) {
        inspect_powershell_password_parameter(view, out, command);
        inspect_convert_to_secure_string(view, out, command);
        inspect_named_secret_options(view, out, command);
        inspect_login_short_password(view, out, command);
        inspect_configure_set(view, out, command);
        inspect_positional_secret_commands(view, out, command);
    }
}

fn may_contain_cli_credential_boundary(text: &str) -> bool {
    text.contains("--")
        || shell::contains_ascii_ci(text, "-password")
        || shell::contains_ascii_ci(text, "-passwd")
        || shell::contains_ascii_ci(text, "-pwd")
        || shell::contains_ascii_ci(text, " -p")
        || shell::contains_ascii_ci(text, "convertto-securestring")
        || shell::contains_ascii_ci(text, "configure")
        || shell::contains_ascii_ci(text, "vault")
}

fn inspect_named_secret_options(
    view: &NormalizedView,
    out: &mut Vec<Span>,
    tokens: &[shell::Token],
) {
    let mut index = 0usize;
    while index < tokens.len() {
        let token = &tokens[index];
        let Some(inline_start) = long_secret_option(&token.value) else {
            index += 1;
            continue;
        };
        if let Some(value_start) = inline_start {
            push_cli_keyed_secret(view, out, token, value_start);
            index += 1;
            continue;
        }
        if let Some(value) = tokens
            .get(index + 1)
            .filter(|value| !looks_like_option(&value.value))
        {
            push_cli_keyed_secret(view, out, value, 0);
            index += 2;
            continue;
        }
        index += 1;
    }
}

fn long_secret_option(value: &str) -> Option<Option<usize>> {
    let option = value.strip_prefix("--")?;
    let separator = option.find(['=', ':']);
    let name = separator.map_or(option, |at| &option[..at]);
    if name.is_empty() {
        return None;
    }
    let normalized = name.to_ascii_lowercase().replace('-', "_");
    if !structural::is_sensitive_key_name(&normalized) || option_names_non_value_source(&normalized)
    {
        return None;
    }
    let inline_start = separator.map(|at| 2 + at + 1);
    Some(inline_start)
}

fn option_names_non_value_source(name: &str) -> bool {
    [
        "_file",
        "_path",
        "_stdin",
        "_fd",
        "_command",
        "_env",
        "_variable",
        "_name",
        "_type",
        "_format",
        "_algorithm",
    ]
    .iter()
    .any(|suffix| name.ends_with(suffix))
}

fn looks_like_option(value: &str) -> bool {
    value.starts_with('-') && value.len() > 1
}

fn inspect_login_short_password(
    view: &NormalizedView,
    out: &mut Vec<Span>,
    tokens: &[shell::Token],
) {
    let login = tokens
        .iter()
        .any(|token| token.value.eq_ignore_ascii_case("login"));
    let has_username = tokens.iter().any(|token| {
        token.value == "-u"
            || token.value.starts_with("-u=")
            || token.value.starts_with("-u:")
            || token.value.eq_ignore_ascii_case("--username")
            || token.value.to_ascii_lowercase().starts_with("--username=")
            || token.value.to_ascii_lowercase().starts_with("--username:")
    });
    if !login || !has_username {
        return;
    }
    for (index, token) in tokens.iter().enumerate() {
        if token.value == "-p" {
            if let Some(value) = tokens
                .get(index + 1)
                .filter(|value| !looks_like_option(&value.value))
            {
                push_cli_password(view, out, value, 0);
            }
        }
    }
}

fn inspect_configure_set(view: &NormalizedView, out: &mut Vec<Span>, tokens: &[shell::Token]) {
    for window in tokens.windows(4) {
        if !window[0].value.eq_ignore_ascii_case("configure")
            || !window[1].value.eq_ignore_ascii_case("set")
        {
            continue;
        }
        let key = window[2].value.replace(['-', '.'], "_");
        if structural::is_sensitive_key_name(&key) && !looks_like_option(&window[3].value) {
            push_cli_keyed_secret(view, out, &window[3], 0);
        }
    }
}

struct PositionalSecretCommand {
    command: &'static str,
    subcommand: &'static str,
}

const POSITIONAL_SECRET_COMMANDS: &[PositionalSecretCommand] = &[PositionalSecretCommand {
    command: "vault",
    subcommand: "login",
}];

fn inspect_positional_secret_commands(
    view: &NormalizedView,
    out: &mut Vec<Span>,
    tokens: &[shell::Token],
) {
    for (index, token) in tokens.iter().enumerate() {
        for spec in POSITIONAL_SECRET_COMMANDS {
            if !shell::basename(&token.value).eq_ignore_ascii_case(spec.command)
                || !tokens
                    .get(index + 1)
                    .is_some_and(|token| token.value.eq_ignore_ascii_case(spec.subcommand))
            {
                continue;
            }
            if let Some(value) = tokens
                .get(index + 2)
                .filter(|value| !looks_like_option(&value.value))
            {
                push_cli_keyed_secret(view, out, value, 0);
            }
        }
    }
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
    let arguments = &tokens[command_index + 1..];
    if !shell::has_powershell_parameter(arguments, "-AsPlainText") {
        return;
    }
    let value = shell::powershell_parameter_value(arguments, "-String").or_else(|| {
        arguments
            .iter()
            .position(|token| !token.value.is_empty() && !token.value.starts_with('-'))
            .map(|index| (index, 0))
    });
    let Some((value_index, value_start)) = value else {
        return;
    };
    let value = &arguments[value_index];
    push_cli_password(view, out, value, value_start);
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
    push_cli_secret(view, out, token, value_start, labels::CMD_PASSWORD);
}

fn push_cli_keyed_secret(
    view: &NormalizedView,
    out: &mut Vec<Span>,
    token: &shell::Token,
    value_start: usize,
) {
    push_cli_secret(view, out, token, value_start, labels::KEYED_SECRET);
}

fn push_cli_secret(
    view: &NormalizedView,
    out: &mut Vec<Span>,
    token: &shell::Token,
    value_start: usize,
    label: &str,
) {
    if value_start >= token.value.len() || value_start >= token.byte_to_raw.len() {
        return;
    }
    let value = token.value[value_start..].trim();
    if !cli_secret_is_material(value) {
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
        label: label.to_string(),
        confidence: Confidence::High,
        source: DetectorId::Rule,
    });
}

pub(crate) fn cli_secret_is_material(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() || value.len() > 256 || value == "-" {
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
        "password"
            | "passwd"
            | "pwd"
            | "secret"
            | "token"
            | "example"
            | "sample"
            | "value"
            | "string"
            | "bearer"
            | "basic"
            | "digest"
            | "ntlm"
            | "negotiate"
            | "oauth"
            | "oauth2"
    ) {
        return false;
    }
    if value.starts_with('$') || value.starts_with('%') {
        return false;
    }
    true
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
    fn convert_to_secure_string_masks_bound_string_parameters() {
        for (raw, expected) in [
            (
                "ConvertTo-SecureString -String:IaiA@eqhtlc -AsPlainText -Force",
                "IaiA@eqhtlc",
            ),
            (
                "ConvertTo-SecureString -STRING:'sécret value' -AsPlainText:$true -Force",
                "sécret value",
            ),
            (
                "ConvertTo-SecureString -String: '-starts-with-dash' -AsPlainText -Force",
                "-starts-with-dash",
            ),
            (
                "ConvertTo-SecureString -String=IaiA@eqhtlc -AsPlainText=$true -Force",
                "IaiA@eqhtlc",
            ),
        ] {
            assert_eq!(
                labels(raw),
                [("CMD_PASSWORD".to_string(), expected.to_string())],
                "{raw}"
            );
        }
        for raw in [
            "ConvertTo-SecureString -Stringify:IaiA@eqhtlc -AsPlainText -Force",
            "ConvertTo-SecureString -String:IaiA@eqhtlc -AsPlainTexts:$true -Force",
        ] {
            assert!(labels(raw).is_empty(), "{raw}: {:?}", labels(raw));
        }
    }

    #[test]
    fn masks_generic_long_secret_options() {
        for raw in [
            "docker login registry.example --password correcthorsebattery",
            "kubectl --token correcthorsebattery get pods",
            "tool --client-secret=correcthorsebattery run",
            "tool --api-key:correcthorsebattery run",
        ] {
            assert_eq!(
                labels(raw),
                [(
                    "KEYED_SECRET".to_string(),
                    "correcthorsebattery".to_string()
                )],
                "{raw}"
            );
        }
        assert_eq!(
            labels(r#"svn --username 'foo' --password 'bar \'bar' https://foo.example.org/svn/"#),
            [("KEYED_SECRET".to_string(), r#"bar \'bar"#.to_string())]
        );
        assert_eq!(
            labels("tool --password x"),
            [("KEYED_SECRET".to_string(), "x".to_string())]
        );
    }

    #[test]
    fn masks_contextual_short_and_positional_cli_secrets() {
        for (raw, label) in [
            (
                "docker login registry.example -u user -p correcthorsebattery",
                "CMD_PASSWORD",
            ),
            ("vault login correcthorsebattery", "KEYED_SECRET"),
            (
                "aws configure set aws_secret_access_key correcthorsebattery",
                "KEYED_SECRET",
            ),
        ] {
            assert_eq!(
                labels(raw),
                [(label.to_string(), "correcthorsebattery".to_string())],
                "{raw}"
            );
        }
    }

    #[test]
    fn cli_boundaries_do_not_mask_metadata_or_cross_commands() {
        for raw in [
            "docker run -p 8080:80 image",
            "docker login -u user; echo -p correcthorsebattery",
            "tool login -u user -profile production",
            "tool --password-file ./password.txt",
            "tool --token-path ./token.txt",
            "tool --secret-name production",
            "kubectl --token $KUBERNETES_TOKEN get pods",
            "docker login -u user --password -",
            "vault status",
            "aws configure set output_format json",
        ] {
            assert!(labels(raw).is_empty(), "{raw}: {:?}", labels(raw));
        }
    }

    #[test]
    fn command_password_templates_are_ignored() {
        for raw in [
            "$obj = Get-NtToken -Password password",
            "$obj = Get-NtToken -Password $password",
        ] {
            assert!(labels(raw).is_empty(), "{raw}: {:?}", labels(raw));
        }
    }
}
