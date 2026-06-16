pub trait InputAdapter {
    fn read(&self, bytes: Vec<u8>) -> Result<String, String>;
}

pub struct TextInput;

impl InputAdapter for TextInput {
    fn read(&self, bytes: Vec<u8>) -> Result<String, String> {
        String::from_utf8(bytes)
            .map_err(|_| "input is not UTF-8 text (binary not supported)".to_string())
    }
}

#[cfg(feature = "pdf")]
pub struct PdfTextInput;

#[cfg(feature = "pdf")]
impl InputAdapter for PdfTextInput {
    fn read(&self, bytes: Vec<u8>) -> Result<String, String> {
        let text = pdf_extract::extract_text_from_mem(&bytes)
            .map_err(|e| format!("could not extract PDF text: {e}"))?;
        if text.trim().is_empty() {
            return Err(
                "PDF contains no extractable text; scanned/image-only PDFs need an OCR adapter"
                    .to_string(),
            );
        }
        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_input_requires_utf8() {
        assert!(TextInput.read(b"hello".to_vec()).is_ok());
        assert!(TextInput.read(vec![0xff, 0xfe]).is_err());
    }
}
