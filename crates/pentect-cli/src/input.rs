pub trait InputAdapter {
    fn read(&self, bytes: Vec<u8>) -> Result<String, String>;
}

pub struct TextInput;
pub struct ImageOcrInput;

impl InputAdapter for TextInput {
    fn read(&self, bytes: Vec<u8>) -> Result<String, String> {
        decode_utf8_text(
            bytes,
            "input is not UTF-8 text (binary not supported)".to_string(),
        )
    }
}

impl InputAdapter for ImageOcrInput {
    fn read(&self, bytes: Vec<u8>) -> Result<String, String> {
        pentect_agent::ocr_image_bytes(&bytes)
    }
}

pub fn decode_utf8_text(bytes: Vec<u8>, err: String) -> Result<String, String> {
    let text = String::from_utf8(bytes).map_err(|_| err)?;
    Ok(text.strip_prefix('\u{feff}').unwrap_or(&text).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_input_requires_utf8() {
        assert!(TextInput.read(b"hello".to_vec()).is_ok());
        assert!(TextInput.read(vec![0xff, 0xfe]).is_err());
    }

    #[test]
    fn text_input_strips_utf8_bom() {
        assert_eq!(
            TextInput
                .read("\u{feff}{\"password\":\"hunter2\"}".as_bytes().to_vec())
                .unwrap(),
            "{\"password\":\"hunter2\"}"
        );
    }
}
