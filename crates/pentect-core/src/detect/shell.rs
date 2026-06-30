#[derive(Debug)]
pub(crate) struct Token {
    pub(crate) value: String,
    pub(crate) byte_to_raw: Vec<usize>,
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
    }
}
