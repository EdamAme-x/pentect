//! Deterministic checksum validators. Each takes the regex-matched text and
//! returns whether it passes its scheme's checksum — the precision lever that
//! lets a permissive pattern avoid false positives (the Presidio approach).
//! Every function is covered by reference test vectors below.

use bip39::{Language, Mnemonic};
use data_encoding::BASE64;
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::LazyLock;

static BIP39_WORDSETS: LazyLock<Vec<(Language, HashSet<&'static str>)>> = LazyLock::new(|| {
    Language::ALL
        .iter()
        .map(|language| (*language, language.word_list().iter().copied().collect()))
        .collect()
});

/// ASCII digits of `s` as 0-9 values, ignoring all other bytes (so separators
/// like spaces/hyphens/dots don't matter).
fn digits(s: &str) -> Vec<u32> {
    s.bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| u32::from(b - b'0'))
        .collect()
}

fn all_same(d: &[u32]) -> bool {
    d.first().is_some_and(|f| d.iter().all(|x| x == f))
}

/// Luhn mod-10 over the digits of `s` (optionally with a fixed digit prefix,
/// e.g. US NPI prepends 80840).
pub fn luhn(s: &str) -> bool {
    luhn_digits(&digits(s))
}

fn luhn_digits(d: &[u32]) -> bool {
    if d.is_empty() {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for &x in d.iter().rev() {
        let mut v = x;
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        double = !double;
    }
    sum.is_multiple_of(10)
}

/// US NPI: Luhn over "80840" + the 10 digits.
pub fn us_npi(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 10 {
        return false;
    }
    let mut v = vec![8, 0, 8, 4, 0];
    v.extend_from_slice(&d);
    luhn_digits(&v)
}

/// Canadian SIN: Luhn over exactly 9 digits.
pub fn ca_sin(s: &str) -> bool {
    digits(s).len() == 9 && luhn(s)
}

/// US ABA routing transit number: weighted (3,7,1) mod-10.
pub fn aba_routing(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 9 || !matches!(d[0], 0 | 1 | 2 | 3 | 6 | 7 | 8) {
        return false;
    }
    let w = [3, 7, 1, 3, 7, 1, 3, 7, 1];
    let sum: u32 = d.iter().zip(w).map(|(a, b)| a * b).sum();
    sum.is_multiple_of(10)
}

/// IBAN total length per ISO 13616 country code (subset; unknown code rejected).
const IBAN_LEN: &[(&str, usize)] = &[
    ("AD", 24),
    ("AE", 23),
    ("AL", 28),
    ("AT", 20),
    ("AZ", 28),
    ("BA", 20),
    ("BE", 16),
    ("BG", 22),
    ("BH", 22),
    ("BR", 29),
    ("BY", 28),
    ("CH", 21),
    ("CR", 22),
    ("CY", 28),
    ("CZ", 24),
    ("DE", 22),
    ("DK", 18),
    ("DO", 28),
    ("EE", 20),
    ("EG", 29),
    ("ES", 24),
    ("FI", 18),
    ("FO", 18),
    ("FR", 27),
    ("GB", 22),
    ("GE", 22),
    ("GI", 23),
    ("GL", 18),
    ("GR", 27),
    ("GT", 28),
    ("HR", 21),
    ("HU", 28),
    ("IE", 22),
    ("IL", 23),
    ("IS", 26),
    ("IT", 27),
    ("JO", 30),
    ("KW", 30),
    ("KZ", 20),
    ("LB", 28),
    ("LC", 32),
    ("LI", 21),
    ("LT", 20),
    ("LU", 20),
    ("LV", 21),
    ("MC", 27),
    ("MD", 24),
    ("ME", 22),
    ("MK", 19),
    ("MR", 27),
    ("MT", 31),
    ("MU", 30),
    ("NL", 18),
    ("NO", 15),
    ("PK", 24),
    ("PL", 28),
    ("PS", 29),
    ("PT", 25),
    ("QA", 29),
    ("RO", 24),
    ("RS", 22),
    ("SA", 24),
    ("SE", 24),
    ("SI", 19),
    ("SK", 24),
    ("SM", 27),
    ("TN", 24),
    ("TR", 26),
    ("UA", 29),
    ("VA", 22),
    ("VG", 24),
    ("XK", 20),
];

/// IBAN: per-country length + ISO 7064 mod-97 (streaming).
pub fn iban_mod97(s: &str) -> bool {
    let canon: String = s
        .bytes()
        .filter(|b| b.is_ascii_alphanumeric())
        .map(|b| b.to_ascii_uppercase() as char)
        .collect();
    if canon.len() < 15 || canon.len() > 34 {
        return false;
    }
    let cc = &canon[..2];
    if !IBAN_LEN.iter().any(|&(c, l)| c == cc && l == canon.len()) {
        return false;
    }
    // Move first 4 chars to the end, map letters A..Z -> 10..35, streaming mod 97.
    let rearranged: String = format!("{}{}", &canon[4..], &canon[..4]);
    let mut m: u32 = 0;
    for ch in rearranged.chars() {
        if ch.is_ascii_digit() {
            m = (m * 10 + (ch as u32 - '0' as u32)) % 97;
        } else if ch.is_ascii_uppercase() {
            let v = ch as u32 - 'A' as u32 + 10; // two digits
            m = (m * 100 + v) % 97;
        } else {
            return false;
        }
    }
    m == 1
}

/// Weighted sum of `d` with weights `w` (same length).
fn wsum(d: &[u32], w: &[i64]) -> i64 {
    d.iter().zip(w).map(|(&a, &b)| a as i64 * b).sum()
}

/// UK NHS number: 10 digits, weighted (10..2) mod-11 check.
pub fn uk_nhs(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 10 {
        return false;
    }
    let w = [10, 9, 8, 7, 6, 5, 4, 3, 2];
    let r = wsum(&d[..9], &w) % 11;
    let check = (11 - r) % 11;
    check != 10 && check == d[9] as i64
}

/// Poland PESEL: 11 digits, weighted check.
pub fn pl_pesel(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 11 || all_same(&d) {
        return false;
    }
    let w = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
    let r = wsum(&d[..10], &w) % 10;
    let check = (10 - r) % 10;
    check == d[10] as i64
}

/// Australia TFN: 9 digits, weighted mod-11 == 0.
pub fn au_tfn(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 9 {
        return false;
    }
    let w = [1, 4, 3, 7, 5, 8, 6, 9, 10];
    wsum(&d, &w) % 11 == 0
}

/// Korea RRN: 13 digits, weighted mod-11 check.
pub fn kr_rrn(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 13 {
        return false;
    }
    let w = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
    let r = wsum(&d[..12], &w) % 11;
    let exp = (11 - r) % 10;
    exp == d[12] as i64
}

/// Netherlands BSN: 8-9 digits, 11-proef (final weight -1).
pub fn nl_bsn(s: &str) -> bool {
    let mut d = digits(s);
    if d.len() == 8 {
        d.insert(0, 0);
    }
    if d.len() != 9 {
        return false;
    }
    let w = [9, 8, 7, 6, 5, 4, 3, 2, -1];
    let sum = wsum(&d, &w);
    sum != 0 && sum % 11 == 0
}

/// Japan My Number: 12 digits, MIC No.85 weighted check digit.
pub fn jp_my_number(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 12 || all_same(&d) {
        return false;
    }
    // P_n indexed from rightmost of the 11-digit payload (d[0..11]).
    let mut sum = 0i64;
    for n in 1..=11usize {
        let p = d[11 - n] as i64;
        let q = if n <= 6 { n as i64 + 1 } else { n as i64 - 5 };
        sum += p * q;
    }
    let r = sum % 11;
    let exp = if r <= 1 { 0 } else { 11 - r };
    exp == d[11] as i64
}

/// Australia ABN: 11 digits, subtract 1 from first, weighted mod-89.
pub fn au_abn(s: &str) -> bool {
    let mut d = digits(s);
    if d.len() != 11 {
        return false;
    }
    d[0] = d[0].wrapping_sub(1);
    let w = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];
    wsum(&d, &w) % 89 == 0
}

/// Australia Medicare: first digit 2-6, weighted mod-10 over 8 digits == d8.
pub fn au_medicare(s: &str) -> bool {
    let d = digits(s);
    if d.len() < 9 || !(2..=6).contains(&d[0]) {
        return false;
    }
    let w = [1, 3, 7, 9, 1, 3, 7, 9];
    (wsum(&d[..8], &w) % 10) == d[8] as i64
}

/// Brazil CPF: 11 digits, double mod-11 check.
pub fn br_cpf(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 11 || all_same(&d) {
        return false;
    }
    let dv = |upto: usize, start_w: i64| -> u32 {
        let sum: i64 = (0..upto).map(|i| d[i] as i64 * (start_w - i as i64)).sum();
        let r = (sum * 10) % 11;
        if r == 10 {
            0
        } else {
            r as u32
        }
    };
    dv(9, 10) == d[9] && dv(10, 11) == d[10]
}

/// Brazil CNPJ: 14 digits, double weighted mod-11 check.
pub fn br_cnpj(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 14 || all_same(&d) {
        return false;
    }
    let cd = |w: &[i64]| -> u32 {
        let r = (wsum(&d[..w.len()], w) % 11) as u32;
        if r < 2 {
            0
        } else {
            11 - r
        }
    };
    cd(&[5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]) == d[12]
        && cd(&[6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]) == d[13]
}

/// Singapore NRIC/FIN: prefix + 7 digits + check letter.
pub fn sg_nric_fin(s: &str) -> bool {
    let t = s.trim();
    let b = t.as_bytes();
    if b.len() != 9 {
        return false;
    }
    let prefix = b[0].to_ascii_uppercase();
    let check = b[8].to_ascii_uppercase();
    if !t[1..8].bytes().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let d: Vec<i64> = t[1..8].bytes().map(|c| (c - b'0') as i64).collect();
    let w = [2, 7, 6, 5, 4, 3, 2];
    let mut sum: i64 = d.iter().zip(w).map(|(a, b)| a * b).sum();
    match prefix {
        b'T' | b'G' => sum += 4,
        b'M' => sum += 3,
        b'S' | b'F' => {}
        _ => return false,
    }
    let r = (sum % 11) as usize;
    let table: &[u8] = match prefix {
        b'S' | b'T' => b"JZIHGFEDCBA",
        b'F' | b'G' => b"XWUTRQPNMLK",
        b'M' => b"KLJNPQRTUWX",
        _ => return false,
    };
    table[r] == check
}

/// US DEA registration number: 2 letters + 7 digits, weighted check.
pub fn us_dea(s: &str) -> bool {
    let t = s.trim();
    let b = t.as_bytes();
    if b.len() != 9 || !b[0].is_ascii_alphabetic() {
        return false;
    }
    let valid_first = b"ABCDEFGHJKLMPRSTUX".contains(&b[0].to_ascii_uppercase());
    if !valid_first || !(b[1].is_ascii_alphabetic() || b[1] == b'9') {
        return false;
    }
    if !t[2..].bytes().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let d: Vec<u32> = t[2..].bytes().map(|c| u32::from(c - b'0')).collect();
    let sum = (d[0] + d[2] + d[4]) + 2 * (d[1] + d[3] + d[5]);
    sum % 10 == d[6]
}

/// Spain NIF/DNI: 8 digits + control letter (mod-23 table).
pub fn es_nif(s: &str) -> bool {
    const LETTERS: &[u8] = b"TRWAGMYFPDXBNJZSQVHLCKE";
    let t = s.trim().to_ascii_uppercase();
    let b = t.as_bytes();
    if b.len() != 9 || !b[..8].iter().all(u8::is_ascii_digit) {
        return false;
    }
    let n: u32 = t[..8].parse().unwrap_or(u32::MAX);
    n != u32::MAX && LETTERS[(n % 23) as usize] == b[8]
}

/// Spain NIE: X/Y/Z prefix + 7 digits + control letter.
pub fn es_nie(s: &str) -> bool {
    const LETTERS: &[u8] = b"TRWAGMYFPDXBNJZSQVHLCKE";
    let t = s.trim().to_ascii_uppercase();
    let b = t.as_bytes();
    if b.len() != 9 || !b[1..8].iter().all(u8::is_ascii_digit) {
        return false;
    }
    let lead = match b[0] {
        b'X' => '0',
        b'Y' => '1',
        b'Z' => '2',
        _ => return false,
    };
    let n: u32 = format!("{lead}{}", &t[1..8]).parse().unwrap_or(u32::MAX);
    n != u32::MAX && LETTERS[(n % 23) as usize] == b[8]
}

/// Germany Steuer-IdNr: 11 digits, ISO 7064 MOD 11,10 + repeated-digit gate.
pub fn de_tax_id(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 11 || d[0] == 0 {
        return false;
    }
    // Structural: exactly one value repeats, twice or thrice (thrice not all
    // consecutive); all others appear once.
    let mut counts = [0u8; 10];
    for &x in &d[..10] {
        counts[x as usize] += 1;
    }
    let twos = counts.iter().filter(|&&c| c == 2).count();
    let threes = counts.iter().filter(|&&c| c == 3).count();
    let ones = counts.iter().filter(|&&c| c == 1).count();
    let structural = (twos == 1 && threes == 0 && ones == 8)
        || (threes == 1 && twos == 0 && ones == 7 && {
            // three positions must not be all consecutive
            let val = counts.iter().position(|&c| c == 3).unwrap() as u32;
            let pos: Vec<usize> = (0..10).filter(|&i| d[i] == val).collect();
            !(pos[1] == pos[0] + 1 && pos[2] == pos[1] + 1)
        });
    if !structural {
        return false;
    }
    let mut product = 10i64;
    for &x in &d[..10] {
        let mut sm = (x as i64 + product) % 10;
        if sm == 0 {
            sm = 10;
        }
        product = (sm * 2) % 11;
    }
    let check = (11 - product) % 10;
    check == d[10] as i64
}

/// US SSN: structural — reject area 000/666/900-999, group 00, serial 0000.
pub fn us_ssn(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 9 {
        return false;
    }
    let area = d[0] * 100 + d[1] * 10 + d[2];
    let group = d[3] * 10 + d[4];
    let serial = d[5] * 1000 + d[6] * 100 + d[7] * 10 + d[8];
    area != 0 && area != 666 && area < 900 && group != 0 && serial != 0
}

/// Finland HETU (henkilötunnus): ddmmyy + century sign + 3-digit individual +
/// mod-31 control character.
pub fn fi_hetu(s: &str) -> bool {
    const CTRL: &[u8] = b"0123456789ABCDEFHJKLMNPRSTUVWXY";
    let t = s.trim().as_bytes();
    if t.len() != 11 {
        return false;
    }
    if !t[0..6].iter().all(u8::is_ascii_digit) || !t[7..10].iter().all(u8::is_ascii_digit) {
        return false;
    }
    if !b"+-YXWVUABCDEF".contains(&t[6].to_ascii_uppercase()) {
        return false;
    }
    let mut n: u64 = 0;
    for &b in t[0..6].iter().chain(&t[7..10]) {
        n = n * 10 + u64::from(b - b'0');
    }
    CTRL[(n % 31) as usize] == t[10].to_ascii_uppercase()
}

/// Italy Codice Fiscale: 16 chars, odd/even table mod-26 control character.
pub fn it_codice_fiscale(s: &str) -> bool {
    #[rustfmt::skip]
    const ODD: [u32; 36] = [
        1, 0, 5, 7, 9, 13, 15, 17, 19, 21,
        1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23,
    ];
    let t = s.trim().to_ascii_uppercase();
    let b = t.as_bytes();
    if b.len() != 16 || !b.iter().all(u8::is_ascii_alphanumeric) {
        return false;
    }
    let idx = |c: u8| -> usize {
        if c.is_ascii_digit() {
            (c - b'0') as usize
        } else {
            (c - b'A') as usize + 10
        }
    };
    let mut sum = 0u32;
    for (i, &c) in b[..15].iter().enumerate() {
        let j = idx(c);
        // 1st/3rd/... characters (0-indexed even) use the odd table.
        sum += if i % 2 == 0 {
            ODD[j]
        } else if j < 10 {
            j as u32
        } else {
            (j - 10) as u32
        };
    }
    b'A' + (sum % 26) as u8 == b[15]
}

/// France NIR (INSEE): 13-digit body + 2-digit key, key = 97 - (body mod 97).
/// Corsica dept 2A/2B (chars 6-7) substitutes to 19/18 before the mod.
pub fn fr_nir(s: &str) -> bool {
    let t: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if t.len() != 15 || !t.as_bytes()[13..15].iter().all(u8::is_ascii_digit) {
        return false;
    }
    let body = match &t[5..7] {
        "2A" => format!("{}19{}", &t[..5], &t[7..13]),
        "2B" => format!("{}18{}", &t[..5], &t[7..13]),
        _ => t[..13].to_string(),
    };
    if body.len() != 13 || !body.bytes().all(|c| c.is_ascii_digit()) {
        return false;
    }
    match (body.parse::<u64>(), t[13..15].parse::<u64>()) {
        (Ok(n), Ok(given)) => given == 97 - (n % 97),
        _ => false,
    }
}

/// Australia ACN (company number): 9 digits, weighted (8..1) mod-10 complement.
pub fn au_acn(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 9 {
        return false;
    }
    let w: [u32; 8] = [8, 7, 6, 5, 4, 3, 2, 1];
    let sum: u32 = d[..8].iter().zip(w).map(|(a, b)| a * b).sum();
    (10 - sum % 10) % 10 == d[8]
}

/// India GSTIN: 15 chars, base-36 Luhn check character over the first 14.
pub fn in_gstin(s: &str) -> bool {
    const CH: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let t = s.trim().to_ascii_uppercase();
    let b = t.as_bytes();
    if b.len() != 15 || !b.iter().all(u8::is_ascii_alphanumeric) {
        return false;
    }
    let val = |c: u8| CH.iter().position(|&x| x == c).unwrap_or(0) as u32;
    let mut total = 0u32;
    let mut factor = 2u32;
    for &c in b[..14].iter().rev() {
        let p = val(c) * factor;
        total += p / 36 + p % 36;
        factor = if factor == 2 { 1 } else { 2 };
    }
    CH[((36 - total % 36) % 36) as usize] == b[14]
}

/// Verhoeff (India Aadhaar): dihedral D5 check == 0.
pub fn verhoeff(s: &str) -> bool {
    const D: [[usize; 10]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ];
    const P: [[usize; 10]; 8] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ];
    let d = digits(s);
    if d.len() != 12 || d[0] < 2 || all_same(&d) {
        return false;
    }
    let mut c = 0usize;
    for (i, &x) in d.iter().rev().enumerate() {
        c = D[c][P[i % 8][x as usize]];
    }
    c == 0
}

/// Base58Check decode (chain alphabet) verifying the trailing 4-byte
/// double-SHA256 checksum; returns the version+payload (no checksum) on success.
fn base58check(s: &str, alphabet: &'static bs58::Alphabet) -> Option<Vec<u8>> {
    use sha2::{Digest, Sha256};
    let raw = bs58::decode(s).with_alphabet(alphabet).into_vec().ok()?;
    if raw.len() < 5 {
        return None;
    }
    let (payload, checksum) = raw.split_at(raw.len() - 4);
    let digest = Sha256::digest(Sha256::digest(payload));
    (&digest[..4] == checksum).then(|| payload.to_vec())
}

/// Bitcoin address: base58check, P2PKH (0x00, '1') or P2SH (0x05, '3').
pub fn btc_address(s: &str) -> bool {
    base58check(s, bs58::Alphabet::BITCOIN).is_some_and(|d| d.len() == 21 && matches!(d[0], 0 | 5))
}

/// Litecoin address: base58check, version 0x30 ('L'), 0x32 ('M'), or 0x05 ('3').
pub fn ltc_address(s: &str) -> bool {
    base58check(s, bs58::Alphabet::BITCOIN)
        .is_some_and(|d| d.len() == 21 && matches!(d[0], 0x30 | 0x32 | 5))
}

/// XRP classic address: base58check over the Ripple alphabet, version 0x00.
pub fn xrp_address(s: &str) -> bool {
    base58check(s, bs58::Alphabet::RIPPLE).is_some_and(|d| d.len() == 21 && d[0] == 0)
}

/// Bitcoin WIF private key: base58check, version 0x80; 33 bytes (uncompressed)
/// or 34 with a trailing 0x01 (compressed).
pub fn wif(s: &str) -> bool {
    base58check(s, bs58::Alphabet::BITCOIN)
        .is_some_and(|d| d[0] == 0x80 && (d.len() == 33 || (d.len() == 34 && d[33] == 1)))
}

const BECH32_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk = 1u32;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// Bitcoin SegWit (bech32 / bech32m) address with HRP "bc".
pub fn btc_bech32(s: &str) -> bool {
    let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
    if has_upper && has_lower {
        return false; // mixed case is invalid by spec
    }
    let s = s.to_ascii_lowercase();
    if !(8..=90).contains(&s.len()) || !s.starts_with("bc1") {
        return false;
    }
    let mut data = Vec::with_capacity(s.len() - 3);
    for c in s[3..].bytes() {
        match BECH32_CHARSET.iter().position(|&x| x == c) {
            Some(v) => data.push(v as u8),
            None => return false,
        }
    }
    if data.len() < 6 {
        return false;
    }
    // hrp_expand("bc") = high bits, separator 0, low bits, then the data.
    let mut values: Vec<u8> = b"bc".iter().map(|c| c >> 5).collect();
    values.push(0);
    values.extend(b"bc".iter().map(|c| c & 31));
    values.extend_from_slice(&data);
    let expected = if data[0] == 0 { 1 } else { 0x2bc8_30a3 }; // bech32 (v0) vs bech32m (v1+)
    bech32_polymod(&values) == expected
}

/// Ethereum address: 40 hex after 0x; if mixed-case, enforce the EIP-55
/// keccak-256 checksum (all-lower / all-upper carry no checksum, accepted).
pub fn eth_address(s: &str) -> bool {
    use sha3::{Digest, Keccak256};
    let body = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(b) => b,
        None => return false,
    };
    if body.len() != 40 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let has_upper = body.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = body.bytes().any(|b| b.is_ascii_lowercase());
    if !(has_upper && has_lower) {
        return true; // no case information to verify
    }
    let hash = Keccak256::digest(body.to_ascii_lowercase().as_bytes());
    for (i, c) in body.bytes().enumerate() {
        if c.is_ascii_alphabetic() {
            let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0xf;
            if (nibble >= 8) != c.is_ascii_uppercase() {
                return false;
            }
        }
    }
    true
}

/// IPv6 address (structural): one `::` at most, 1-4 hex per group, correct group
/// count, optional %zone and /prefix stripped first.
pub fn ipv6(s: &str) -> bool {
    let s = s.split('%').next().unwrap_or(s);
    let s = s.split('/').next().unwrap_or(s);
    if !s.contains(':') || s.contains(":::") {
        return false;
    }
    if s == "::" {
        return false;
    }
    let compressed = s.matches("::").count();
    if compressed > 1 {
        return false;
    }
    let groups: Vec<&str> = s.split(':').collect();
    for g in &groups {
        if !g.is_empty() && (g.len() > 4 || !g.bytes().all(|b| b.is_ascii_hexdigit())) {
            return false;
        }
    }
    let nonempty = groups.iter().filter(|g| !g.is_empty()).count();
    if compressed == 0 {
        nonempty == 8 && groups.iter().all(|g| !g.is_empty())
    } else {
        nonempty <= 7
    }
}

/// BIP-39 mnemonic seed phrase: a contiguous run of 12/15/18/21/24 words from
/// an official wordlist with a valid checksum. The `bip39` crate handles all
/// enabled BIP-39 languages and Unicode normalization; checksum validation keeps
/// false positives negligible.
pub fn bip39_mnemonic(s: &str) -> bool {
    let mut normalized = Cow::Borrowed(s);
    Mnemonic::normalize_utf8_cow(&mut normalized);
    let words: Vec<String> = normalized
        .split_whitespace()
        .map(str::to_lowercase)
        .collect();
    for &len in &[24usize, 21, 18, 15, 12] {
        if words.len() < len {
            continue;
        }
        for w in words.windows(len) {
            if bip39_window_valid(w) {
                return true;
            }
        }
    }
    false
}

pub(crate) fn bip39_mnemonic_window(words: &[&str]) -> bool {
    if !matches!(words.len(), 12 | 15 | 18 | 21 | 24) {
        return false;
    }
    let words = words
        .iter()
        .map(|word| {
            let mut normalized = Cow::Borrowed(*word);
            Mnemonic::normalize_utf8_cow(&mut normalized);
            normalized.to_lowercase()
        })
        .collect::<Vec<_>>();
    bip39_window_valid(&words)
}

pub(crate) fn bip39_language_mask(word: &str) -> u16 {
    let mut normalized = Cow::Borrowed(word);
    Mnemonic::normalize_utf8_cow(&mut normalized);
    let word = normalized.to_lowercase();
    let mut mask = 0u16;
    for (index, (_, wordset)) in BIP39_WORDSETS.iter().enumerate() {
        if wordset.contains(word.as_str()) {
            mask |= 1 << index;
        }
    }
    mask
}

fn bip39_window_valid(words: &[String]) -> bool {
    let mut phrase = None;
    for (language, wordset) in BIP39_WORDSETS.iter() {
        if !words.iter().all(|word| wordset.contains(word.as_str())) {
            continue;
        }
        let phrase = phrase.get_or_insert_with(|| words.join(" "));
        if Mnemonic::parse_in(*language, phrase.as_str()).is_ok() {
            return true;
        }
    }
    false
}

/// Local account names captured from home-directory paths. This is not a
/// checksum; it filters obvious shared/system pseudo-users so path masking does
/// not erase useful public directory context.
pub fn local_username(s: &str) -> bool {
    let name = s.trim();
    if name.is_empty() || name.len() > 64 {
        return false;
    }
    if name == "." || name == ".." {
        return false;
    }
    if name.chars().all(|c| c == '.' || c.is_whitespace()) {
        return false;
    }
    if name.chars().any(|c| {
        c.is_control() || matches!(c, '\\' | '/' | ':' | '"' | '<' | '>' | '|' | '?' | '*')
    }) {
        return false;
    }
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "all users" | "default" | "default user" | "public" | "shared"
    )
}

/// RFC 7617 Basic credentials are base64(user-id ":" password). Token68 allows
/// omitted padding, so normalize before decoding. Requiring a non-edge colon
/// removes prose and arbitrary base64-looking samples without hardcoding values.
fn basic_auth_token68(s: &str) -> bool {
    let token = s.trim();
    if token.len() < 8
        || token.len() % 4 == 1
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
    {
        return false;
    }
    let padded = match token.len() % 4 {
        0 => Cow::Borrowed(token),
        2 => Cow::Owned(format!("{token}==")),
        3 => Cow::Owned(format!("{token}=")),
        _ => return false,
    };
    let Ok(decoded) = BASE64.decode(padded.as_bytes()) else {
        return false;
    };
    let Some(colon) = decoded.iter().position(|b| *b == b':') else {
        return false;
    };
    colon > 0 && colon + 1 < decoded.len()
}

/// A checksum gate applied to a regex match before it becomes a span.
#[derive(Clone, Copy, Debug)]
pub enum Validator {
    None,
    Luhn,
    UsNpi,
    CaSin,
    AbaRouting,
    IbanMod97,
    UkNhs,
    PlPesel,
    AuTfn,
    KrRrn,
    NlBsn,
    JpMyNumber,
    AuAbn,
    AuMedicare,
    BrCpf,
    BrCnpj,
    SgNricFin,
    UsDea,
    EsNif,
    EsNie,
    DeTaxId,
    Verhoeff,
    BtcAddress,
    LtcAddress,
    XrpAddress,
    Wif,
    UsSsn,
    BtcBech32,
    EthAddress,
    Bip39,
    Ipv6,
    FiHetu,
    ItFiscalCode,
    FrNir,
    AuAcn,
    InGstin,
    LocalUsername,
    BasicAuthToken68,
    DbConnectionString,
}

impl Validator {
    /// Resolve a validator by its snake_case name (for TOML rule packs), so a
    /// user can add a checksum-gated detector from data. Unknown names are an
    /// error at the call site.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "none" => Validator::None,
            "luhn" => Validator::Luhn,
            "us_npi" => Validator::UsNpi,
            "ca_sin" => Validator::CaSin,
            "aba_routing" => Validator::AbaRouting,
            "iban_mod97" => Validator::IbanMod97,
            "uk_nhs" => Validator::UkNhs,
            "pl_pesel" => Validator::PlPesel,
            "au_tfn" => Validator::AuTfn,
            "kr_rrn" => Validator::KrRrn,
            "nl_bsn" => Validator::NlBsn,
            "jp_my_number" => Validator::JpMyNumber,
            "au_abn" => Validator::AuAbn,
            "au_medicare" => Validator::AuMedicare,
            "br_cpf" => Validator::BrCpf,
            "br_cnpj" => Validator::BrCnpj,
            "sg_nric_fin" => Validator::SgNricFin,
            "us_dea" => Validator::UsDea,
            "es_nif" => Validator::EsNif,
            "es_nie" => Validator::EsNie,
            "de_tax_id" => Validator::DeTaxId,
            "verhoeff" => Validator::Verhoeff,
            "btc_address" => Validator::BtcAddress,
            "ltc_address" => Validator::LtcAddress,
            "xrp_address" => Validator::XrpAddress,
            "wif" => Validator::Wif,
            "us_ssn" => Validator::UsSsn,
            "btc_bech32" => Validator::BtcBech32,
            "eth_address" => Validator::EthAddress,
            "bip39" => Validator::Bip39,
            "ipv6" => Validator::Ipv6,
            "fi_hetu" => Validator::FiHetu,
            "it_codice_fiscale" => Validator::ItFiscalCode,
            "fr_nir" => Validator::FrNir,
            "au_acn" => Validator::AuAcn,
            "in_gstin" => Validator::InGstin,
            "local_username" => Validator::LocalUsername,
            "basic_auth_token68" => Validator::BasicAuthToken68,
            "db_connection_string" => Validator::DbConnectionString,
            _ => return None,
        })
    }

    pub fn accepts(self, s: &str) -> bool {
        match self {
            Validator::None => true,
            Validator::Luhn => luhn(s),
            Validator::UsNpi => us_npi(s),
            Validator::CaSin => ca_sin(s),
            Validator::AbaRouting => aba_routing(s),
            Validator::IbanMod97 => iban_mod97(s),
            Validator::UkNhs => uk_nhs(s),
            Validator::PlPesel => pl_pesel(s),
            Validator::AuTfn => au_tfn(s),
            Validator::KrRrn => kr_rrn(s),
            Validator::NlBsn => nl_bsn(s),
            Validator::JpMyNumber => jp_my_number(s),
            Validator::AuAbn => au_abn(s),
            Validator::AuMedicare => au_medicare(s),
            Validator::BrCpf => br_cpf(s),
            Validator::BrCnpj => br_cnpj(s),
            Validator::SgNricFin => sg_nric_fin(s),
            Validator::UsDea => us_dea(s),
            Validator::EsNif => es_nif(s),
            Validator::EsNie => es_nie(s),
            Validator::DeTaxId => de_tax_id(s),
            Validator::Verhoeff => verhoeff(s),
            Validator::BtcAddress => btc_address(s),
            Validator::LtcAddress => ltc_address(s),
            Validator::XrpAddress => xrp_address(s),
            Validator::Wif => wif(s),
            Validator::UsSsn => us_ssn(s),
            Validator::BtcBech32 => btc_bech32(s),
            Validator::EthAddress => eth_address(s),
            Validator::Bip39 => bip39_mnemonic(s),
            Validator::Ipv6 => ipv6(s),
            Validator::FiHetu => fi_hetu(s),
            Validator::ItFiscalCode => it_codice_fiscale(s),
            Validator::FrNir => fr_nir(s),
            Validator::AuAcn => au_acn(s),
            Validator::InGstin => in_gstin(s),
            Validator::LocalUsername => local_username(s),
            Validator::BasicAuthToken68 => basic_auth_token68(s),
            Validator::DbConnectionString => db_connection_string(s),
        }
    }
}

pub fn db_connection_string(s: &str) -> bool {
    // RFC 3986 userinfo can be concrete credentials, but documentation often
    // spells optional userinfo with bracket/angle/template markers. The regex
    // finds URI-shaped candidates; this validator rejects only those public
    // template/redaction forms and keeps ordinary `user:password@host` strings.
    let Some((_, rest)) = s.split_once("://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or_default().trim();
    let Some((userinfo, host)) = authority.rsplit_once('@') else {
        return false;
    };
    if host.is_empty() || userinfo_is_template_or_redaction(userinfo) {
        return false;
    }
    let Some((user, password)) = userinfo.split_once(':') else {
        return false;
    };
    !user.is_empty()
        && !password.is_empty()
        && !userinfo_part_is_template_or_redaction(user)
        && !userinfo_part_is_template_or_redaction(password)
}

fn userinfo_is_template_or_redaction(userinfo: &str) -> bool {
    userinfo_part_is_template_or_redaction(userinfo)
        || userinfo
            .split(':')
            .any(userinfo_part_is_template_or_redaction)
}

fn userinfo_part_is_template_or_redaction(part: &str) -> bool {
    let part = part.trim();
    part.is_empty()
        || part
            .bytes()
            .any(|b| matches!(b, b'[' | b']' | b'{' | b'}' | b'<' | b'>' | b'*'))
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! vectors {
        ($f:expr, $($s:expr => $ok:expr),+ $(,)?) => {
            $(assert_eq!($f($s), $ok, "{}: {:?}", stringify!($f), $s);)+
        };
    }

    #[test]
    fn checksums_match_reference_vectors() {
        vectors!(luhn, "4242424242424242" => true, "4242424242424243" => false, "00123456782" => true);
        vectors!(us_npi, "1234567893" => true, "1234567894" => false);
        vectors!(ca_sin, "000000000" => true, "000000001" => false);
        vectors!(aba_routing, "021000021" => true, "021000022" => false, "421000021" => false, "322271627" => true);
        vectors!(iban_mod97,
            "DE89370400440532013000" => true,
            "GB82WEST12345698765432" => true,
            "DE8937040044053201300" => false,
            "ZZ8937040044053201300" => false);
        vectors!(uk_nhs, "9434767016" => true, "9434767011" => false);
        vectors!(pl_pesel, "44051401359" => true, "44051401358" => false);
        vectors!(au_tfn, "123456782" => true, "123456783" => false);
        vectors!(kr_rrn, "9001011123459" => true, "9001011123450" => false);
        vectors!(nl_bsn, "111222333" => true, "111222334" => false, "000000000" => false, "200432138" => true);
        vectors!(jp_my_number, "123456789018" => true, "987654321093" => true, "123456789011" => false, "000000000000" => false);
        vectors!(au_abn, "51824753556" => true, "51824753557" => false);
        vectors!(au_medicare, "2951234577" => true, "2951234587" => false);
        vectors!(br_cpf, "11144477735" => true, "11144477730" => false, "11111111111" => false);
        vectors!(br_cnpj, "11222333000181" => true, "11222333000180" => false);
        vectors!(sg_nric_fin, "S1234567D" => true, "T0123456G" => true, "S1234567A" => false, "G7654321L" => true);
        vectors!(us_dea, "AB1234563" => true, "AB1234567" => false, "FH3571595" => true, "II1234563" => false);
        vectors!(es_nif, "12345678Z" => true, "12345678A" => false);
        vectors!(es_nie, "X1234567L" => true, "X1234567A" => false);
        vectors!(de_tax_id, "86095742719" => true, "79569910383" => true, "12345678903" => false, "02345678901" => false);
        vectors!(verhoeff, "234567890124" => true, "234567890121" => false, "345678901238" => true, "111111111111" => false);
        vectors!(us_ssn, "219099998" => true, "000099998" => false, "666099998" => false, "219009998" => false, "219090000" => false);
        vectors!(fi_hetu, "131052-308T" => true, "131052X308T" => true, "131052-308U" => false, "131052G308T" => false);
        vectors!(it_codice_fiscale, "RSSMRA85T10A562S" => true, "RSSMRA85M01H501Q" => true, "RSSMRA85T10A562A" => false);
        vectors!(fr_nir, "180047509112541" => true, "180047509112556" => false);
        vectors!(au_acn, "004085616" => true, "004085617" => false);
        vectors!(in_gstin, "27AAPFU0939F1ZV" => true, "27AAPFU0939F1ZX" => false);
    }

    #[test]
    fn basic_auth_token68_requires_decoded_user_pass() {
        vectors!(basic_auth_token68,
            "dXNlcjpwYXNz" => true,
            "d3p3bTpqQGNs" => true,
            "eXc6ZXR1ZW1vWA==" => true,
            "p4ssw0rd" => false,
            "something" => false,
            "dXNlcm9ubHk=" => false,
            "OnBhc3M=" => false);
    }

    #[test]
    fn db_connection_strings_reject_uri_templates_only() {
        vectors!(db_connection_string,
            "postgresql://admin:s3cr3t@db.host:5432/sales" => true,
            "mysql://user:pass@localhost" => true,
            "mysql://ofh:ab12c!?@db.example.internal/name" => true,
            "postgresql://[user[:password]@][host][:port][" => false,
            "mongodb://username:<password>@cluster0.example.com:27017" => false,
            "redis://***:***@localhost:6379" => false);
    }

    #[test]
    fn local_username_filters_shared_home_directories() {
        vectors!(local_username,
            "alice" => true,
            "Alice Smith" => true,
            "山田太郎" => true,
            "Public" => false,
            "Shared" => false,
            "Default User" => false,
            ".." => false,
            "alice/project" => false);
    }

    #[test]
    fn base58check_crypto_validators() {
        use sha2::{Digest, Sha256};
        // Build a valid base58check string for a version+20-byte payload, so no
        // real address/key literal is needed in source.
        let make = |ver: u8, body: &[u8], alpha: &'static bs58::Alphabet| {
            let mut p = vec![ver];
            p.extend_from_slice(body);
            let cs = Sha256::digest(Sha256::digest(&p));
            p.extend_from_slice(&cs[..4]);
            bs58::encode(&p).with_alphabet(alpha).into_string()
        };
        let b = [0x11u8; 20];
        assert!(btc_address(&make(0x00, &b, bs58::Alphabet::BITCOIN)));
        assert!(ltc_address(&make(0x30, &b, bs58::Alphabet::BITCOIN)));
        assert!(xrp_address(&make(0x00, &b, bs58::Alphabet::RIPPLE)));
        // Bitcoin genesis address (public) and a tampered copy.
        assert!(btc_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
        assert!(!btc_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"));
        // WIF: version 0x80 + 32-byte key.
        let wif_str = make(0x80, &[0x22u8; 32], bs58::Alphabet::BITCOIN);
        assert!(wif(&wif_str));
        assert!(!wif("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")); // valid base58check, wrong version
    }

    #[test]
    fn bech32_and_eip55_validators() {
        // BIP-173 reference v0 address.
        assert!(btc_bech32("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
        assert!(!btc_bech32("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5")); // bad checksum
        assert!(!btc_bech32("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3llr")); // wrong HRP
                                                                           // EIP-55 reference addresses.
        assert!(eth_address("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"));
        assert!(eth_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"));
        assert!(!eth_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1Beaed")); // case flip
        assert!(!eth_address("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d35")); // 39 hex
    }

    #[test]
    fn bip39_mnemonic_validator() {
        assert!(bip39_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ));
        assert!(bip39_mnemonic(
            "legal winner thank year wave sausage worth useful legal winner thank yellow"
        ));
        assert!(bip39_mnemonic(
            "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あおぞら"
        ));
        // Right length & wordlist but wrong checksum (last word swapped).
        assert!(!bip39_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo"
        ));
        // A non-wordlist token.
        assert!(!bip39_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon xyzzy"
        ));
        assert!(!bip39_mnemonic("just three words here")); // wrong count
    }

    #[test]
    fn ipv6_structural_validator() {
        assert!(ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
        assert!(ipv6("2001:db8::8a2e:370:7334"));
        assert!(ipv6("::1"));
        assert!(ipv6("fe80::1%eth0"));
        assert!(!ipv6("::")); // too ambiguous in source text and placeholders
        assert!(!ipv6("2001:db8::8a2e::7334")); // two ::
        assert!(!ipv6("2001:db8:85a3:0:0:8a2e:370:7334:9999")); // 9 groups
        assert!(!ipv6("00:1A:2B:3C:4D:5E")); // MAC, not 8 groups
        assert!(!ipv6("12:34:56")); // not IPv6
    }
}
