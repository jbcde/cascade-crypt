use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum DecodeError {
    Base64(base64::DecodeError),
    InvalidFormat,
}

impl From<base64::DecodeError> for DecodeError {
    fn from(e: base64::DecodeError) -> Self {
        DecodeError::Base64(e)
    }
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Base64(e) => write!(f, "Base64 decode error: {}", e),
            DecodeError::InvalidFormat => write!(f, "Invalid encoded format"),
        }
    }
}

/// Minimum padded size in bytes (before base64 encoding).
/// This hides the size of small files. 1KB provides reasonable privacy
/// while keeping overhead acceptable for tiny files.
const MIN_PADDED_SIZE: usize = 1024;

/// Length prefix size in bytes (u64).
const PREFIX_LEN: usize = 8;

/// Encode binary data to base64 string with minimum padding.
/// Format: [8-byte LE length][original data][random padding to MIN_PADDED_SIZE]
/// This hides the exact size of small files.
#[inline]
pub fn encode(data: &[u8]) -> String {
    let len = data.len() as u64;
    let total_size = (PREFIX_LEN + data.len()).max(MIN_PADDED_SIZE);
    let padding_len = total_size - PREFIX_LEN - data.len();

    let mut padded = Vec::with_capacity(total_size);
    padded.extend_from_slice(&len.to_le_bytes());
    padded.extend_from_slice(data);

    // Add random padding
    if padding_len > 0 {
        let mut padding = vec![0u8; padding_len];
        rand::rng().fill_bytes(&mut padding);
        padded.extend_from_slice(&padding);
    }

    STANDARD.encode(&padded)
}

/// Decode base64 string to binary data, stripping padding.
/// Expects length-prefixed format: [8-byte LE length][data][padding].
#[inline]
pub fn decode(encoded: &str) -> Result<Zeroizing<Vec<u8>>, DecodeError> {
    let padded = Zeroizing::new(STANDARD.decode(encoded)?);

    if padded.len() >= PREFIX_LEN {
        let len = u64::from_le_bytes([
            padded[0], padded[1], padded[2], padded[3],
            padded[4], padded[5], padded[6], padded[7],
        ]) as usize;

        if len <= padded.len() - PREFIX_LEN {
            return Ok(Zeroizing::new(padded[PREFIX_LEN..PREFIX_LEN + len].to_vec()));
        }
    }

    Err(DecodeError::InvalidFormat)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let original = b"Hello, cascrypt!";
        let encoded = encode(original);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(original.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_binary_data() {
        let binary: Vec<u8> = (0..=255).collect();
        let encoded = encode(&binary);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(binary.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_empty_data() {
        let original: &[u8] = b"";
        let encoded = encode(original);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(original, decoded.as_slice());
    }

    #[test]
    fn test_small_files_padded() {
        // Small files should be padded to minimum size
        let small = b"tiny";
        let encoded = encode(small);
        let decoded_raw = STANDARD.decode(&encoded).unwrap();
        // Should be at least MIN_PADDED_SIZE bytes before base64
        assert!(decoded_raw.len() >= MIN_PADDED_SIZE);
        // But decode should return original
        let decoded = decode(&encoded).unwrap();
        assert_eq!(small.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_large_files_not_over_padded() {
        // Large files should only have length prefix overhead
        let large: Vec<u8> = vec![0x42; 2048];
        let encoded = encode(&large);
        let decoded_raw = STANDARD.decode(&encoded).unwrap();
        // Should be exactly PREFIX_LEN + data length (no extra padding)
        assert_eq!(decoded_raw.len(), PREFIX_LEN + large.len());
        // Decode should return original
        let decoded = decode(&encoded).unwrap();
        assert_eq!(large.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_raw_base64_rejected() {
        // Data without length prefix should be rejected (no legacy fallback)
        let raw_data = b"Raw data without length prefix";
        let raw_encoded = STANDARD.encode(raw_data);
        assert!(decode(&raw_encoded).is_err());
    }
}
