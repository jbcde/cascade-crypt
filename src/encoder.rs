use base64::{engine::general_purpose::STANDARD, Engine};

/// Encode binary data to base64 string
#[inline]
pub fn encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// Decode base64 string to binary data
#[inline]
pub fn decode(encoded: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD.decode(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let original = b"Hello, cascade-crypt!";
        let encoded = encode(original);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(original.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_binary_data() {
        let binary: Vec<u8> = (0..=255).collect();
        let encoded = encode(&binary);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(binary, decoded);
    }
}
