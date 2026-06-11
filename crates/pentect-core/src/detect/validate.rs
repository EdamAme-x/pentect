//! Deterministic checksum validators. Each takes the regex-matched text and
//! returns whether it passes its scheme's checksum — the precision lever that
//! lets a permissive pattern avoid false positives (the Presidio approach).
//! Every function is covered by reference test vectors below.

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
}

impl Validator {
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
        }
    }
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
    }
}
