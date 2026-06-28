pub(crate) fn next_shell_word(text: &str, start: usize) -> Option<(String, usize, usize)> {
    let mut word_start = start;
    while word_start < text.len() {
        let ch = text[word_start..].chars().next()?;
        if !ch.is_whitespace() {
            break;
        }
        word_start += ch.len_utf8();
    }
    if word_start >= text.len() {
        return None;
    }
    let first = text[word_start..].chars().next()?;
    if matches!(first, '\'' | '"') {
        let mut end = word_start + first.len_utf8();
        let mut word = String::new();
        while end < text.len() {
            let ch = text[end..].chars().next()?;
            end += ch.len_utf8();
            if ch == first {
                return Some((word, word_start, end));
            }
            word.push(ch);
        }
        return Some((word, word_start, end));
    }
    let mut end = word_start;
    while end < text.len() {
        let ch = text[end..].chars().next()?;
        if ch.is_whitespace() {
            break;
        }
        end += ch.len_utf8();
    }
    Some((text[word_start..end].to_string(), word_start, end))
}

pub(crate) fn shell_quote_unix(value: &str) -> String {
    if is_simple_shell_word(value) {
        return value.to_string();
    }
    if value.is_empty() {
        return "''".to_string();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

pub(crate) fn powershell_word(value: &str) -> String {
    if is_simple_shell_word(value) {
        value.to_string()
    } else {
        powershell_quote(value)
    }
}

fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn is_simple_shell_word(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}
