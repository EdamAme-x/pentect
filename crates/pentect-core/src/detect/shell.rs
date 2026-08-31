#[derive(Debug)]
pub(crate) struct Token {
    pub(crate) value: String,
    pub(crate) byte_to_raw: Vec<usize>,
}

enum PowerShellParameterForm {
    Separate,
    Bound(usize),
}

/// Returns the token and decoded-byte offset of a PowerShell named parameter's
/// value. PowerShell officially supports both `-Name Value` and `-Name:Value`.
/// We also accept `-Name=Value` defensively, but only after an exact,
/// case-insensitive parameter-name match.
pub(crate) fn powershell_parameter_value(tokens: &[Token], name: &str) -> Option<(usize, usize)> {
    tokens.iter().enumerate().find_map(|(index, token)| {
        match powershell_parameter_form(&token.value, name)? {
            PowerShellParameterForm::Separate => tokens.get(index + 1).map(|_| (index + 1, 0)),
            PowerShellParameterForm::Bound(start) if start < token.value.len() => {
                Some((index, start))
            }
            PowerShellParameterForm::Bound(_) => tokens.get(index + 1).map(|_| (index + 1, 0)),
        }
    })
}

pub(crate) fn has_powershell_parameter(tokens: &[Token], name: &str) -> bool {
    tokens
        .iter()
        .any(|token| powershell_parameter_form(&token.value, name).is_some())
}

fn powershell_parameter_form(value: &str, name: &str) -> Option<PowerShellParameterForm> {
    if value.eq_ignore_ascii_case(name) {
        return Some(PowerShellParameterForm::Separate);
    }
    let prefix = value.get(..name.len())?;
    if !prefix.eq_ignore_ascii_case(name) {
        return None;
    }
    matches!(value.as_bytes().get(name.len()), Some(b':' | b'='))
        .then_some(PowerShellParameterForm::Bound(name.len() + 1))
}

pub(crate) fn tokens(line: &str, base: usize) -> Vec<Token> {
    let mut out = Vec::new();
    let chars = line.char_indices().collect::<Vec<_>>();
    let mut i = 0;
    while i < chars.len() {
        while i < chars.len() && delimits_token(chars[i].1) {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }

        let mut value = String::new();
        let mut byte_to_raw = Vec::new();
        let mut quote = None;
        while i < chars.len() {
            let (raw_offset, ch) = chars[i];
            if quote.is_none() && delimits_token(ch) {
                break;
            }
            if quote.is_none() && is_control(ch) {
                break;
            }
            if ch == '\\'
                && quote.is_some()
                && chars
                    .get(i + 1)
                    .is_some_and(|(_, next)| Some(*next) == quote)
            {
                let (quoted_offset, quoted) = chars[i + 1];
                value.push(quoted);
                byte_to_raw
                    .extend((0..quoted.len_utf8()).map(|offset| base + quoted_offset + offset));
                i += 2;
                continue;
            }
            if matches!(ch, '\'' | '"') {
                if quote == Some(ch) {
                    quote = None;
                    i += 1;
                    continue;
                }
                if quote.is_none() {
                    quote = Some(ch);
                    i += 1;
                    continue;
                }
            }
            value.push(ch);
            byte_to_raw.extend((0..ch.len_utf8()).map(|offset| base + raw_offset + offset));
            i += 1;
        }
        if !value.is_empty() {
            out.push(Token { value, byte_to_raw });
        }
        while i < chars.len() && !delimits_token(chars[i].1) && is_control(chars[i].1) {
            i += 1;
        }
    }
    out
}

/// Splits tokenized shell text at control operators without interpreting the
/// command itself. Keeping this boundary in one place prevents detectors from
/// associating an option in one command with a value in the next command.
pub(crate) fn command_slices<'a>(tokens: &'a [Token], text: &str) -> Vec<&'a [Token]> {
    if tokens.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut start = 0usize;
    for index in 0..tokens.len().saturating_sub(1) {
        let Some(gap_start) = tokens[index]
            .byte_to_raw
            .last()
            .and_then(|offset| offset.checked_add(1))
        else {
            continue;
        };
        let Some(gap_end) = tokens[index + 1].byte_to_raw.first().copied() else {
            continue;
        };
        if text
            .get(gap_start..gap_end)
            .is_some_and(|gap| gap.chars().any(is_control))
        {
            out.push(&tokens[start..=index]);
            start = index + 1;
        }
    }
    out.push(&tokens[start..]);
    out
}

pub(crate) fn basename(value: &str) -> &str {
    let base = value.rsplit(['/', '\\']).next().unwrap_or(value);
    if base.len() > 4 {
        let suffix_at = base.len() - 4;
        if base
            .get(suffix_at..)
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".exe"))
        {
            return base.get(..suffix_at).unwrap_or(base);
        }
    }
    base
}

pub(crate) fn contains_ascii_ci(haystack: &str, needle: &str) -> bool {
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn delimits_token(ch: char) -> bool {
    ch.is_ascii_whitespace()
}

fn is_control(ch: char) -> bool {
    matches!(ch, ';' | '|' | '<' | '>')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_preserve_utf8_byte_mapping() {
        let got = tokens("Get-Thing -Password sécure123", 10);
        let value = got.iter().find(|token| token.value == "sécure123").unwrap();
        assert_eq!(value.byte_to_raw.len(), value.value.len());
        assert_eq!(value.byte_to_raw[0], 30);
        assert_eq!(basename("C:\\Tools\\CURL.EXE"), "CURL");

        let escaped = tokens(r#"tool --password 'bar \'bar' https://example.test"#, 0);
        assert_eq!(escaped[2].value, "bar 'bar");
        assert_eq!(escaped[3].value, "https://example.test");
    }

    #[test]
    fn powershell_parameters_require_an_exact_name_and_preserve_value_offsets() {
        let tokens = tokens("Thing -VaLuE:'sécret' -Values:not-secret", 10);
        let (index, start) = powershell_parameter_value(&tokens, "-Value").unwrap();
        let value = &tokens[index];
        assert_eq!(&value.value[start..], "sécret");
        assert_eq!(value.byte_to_raw[start], 24);
        assert!(!has_powershell_parameter(&tokens, "-ValuesX"));
        assert!(powershell_parameter_value(&tokens, "-Val").is_none());
    }

    #[test]
    fn command_slices_do_not_cross_control_operators() {
        let raw = "docker login -u user; echo -p project | tool --token secretvalue";
        let tokens = tokens(raw, 0);
        let commands = command_slices(&tokens, raw)
            .into_iter()
            .map(|tokens| {
                tokens
                    .iter()
                    .map(|token| token.value.as_str())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            commands,
            [
                vec!["docker", "login", "-u", "user"],
                vec!["echo", "-p", "project"],
                vec!["tool", "--token", "secretvalue"],
            ]
        );
    }
}
