use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;

/// Minimum padded size in bytes (before base64 encoding).
/// This hides the size of small files. 1KB provides reasonable privacy
/// while keeping overhead acceptable for tiny files.
const MIN_PADDED_SIZE: usize = 1024;

/// Maximum encodable size (u32::MAX, ~4 GiB).
/// The length prefix is 4 bytes, so data larger than this cannot be represented.
const MAX_ENCODE_SIZE: usize = u32::MAX as usize;

/// Encode binary data to base64 string with minimum padding.
/// Format: [4-byte LE length][original data][random padding to MIN_PADDED_SIZE]
/// This hides the exact size of small files.
///
/// Returns an error if `data` exceeds 4 GiB (the length prefix is 4 bytes).
#[inline]
pub fn encode(data: &[u8]) -> Result<String, &'static str> {
    if data.len() > MAX_ENCODE_SIZE {
        return Err("data exceeds maximum encodable size (4 GiB)");
    }
    let len = data.len() as u32;
    let total_size = (4 + data.len()).max(MIN_PADDED_SIZE);
    let padding_len = total_size - 4 - data.len();

    let mut padded = Vec::with_capacity(total_size);
    padded.extend_from_slice(&len.to_le_bytes());
    padded.extend_from_slice(data);

    // Add random padding
    if padding_len > 0 {
        let mut padding = vec![0u8; padding_len];
        rand::thread_rng().fill_bytes(&mut padding);
        padded.extend_from_slice(&padding);
    }

    Ok(STANDARD.encode(&padded))
}

/// Decode base64 string to binary data, stripping padding.
/// Backward compatible: tries length-prefixed format first,
/// falls back to legacy format (raw base64) if length is invalid.
#[inline]
pub fn decode(encoded: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let padded = STANDARD.decode(encoded)?;

    // Try format with 4-byte length prefix
    if padded.len() >= 4 {
        let len = u32::from_le_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;

        // Valid format: length makes sense and data would fit
        if len <= padded.len() - 4 {
            return Ok(padded[4..4 + len].to_vec());
        }
    }

    // Legacy format: raw data without length prefix
    Ok(padded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let original = b"Hello, cascrypt!";
        let encoded = encode(original).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(original.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_binary_data() {
        let binary: Vec<u8> = (0..=255).collect();
        let encoded = encode(&binary).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(binary, decoded);
    }

    #[test]
    fn test_empty_data() {
        let original: &[u8] = b"";
        let encoded = encode(original).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(original, decoded.as_slice());
    }

    #[test]
    fn test_small_files_padded() {
        // Small files should be padded to minimum size
        let small = b"tiny";
        let encoded = encode(small).unwrap();
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
        let encoded = encode(&large).unwrap();
        let decoded_raw = STANDARD.decode(&encoded).unwrap();
        // Should be exactly 4 + data length (no extra padding)
        assert_eq!(decoded_raw.len(), 4 + large.len());
        // Decode should return original
        let decoded = decode(&encoded).unwrap();
        assert_eq!(large, decoded);
    }

    #[test]
    fn test_legacy_format_compatibility() {
        // Old files were encoded without length prefix - verify backward compat
        let legacy_data = b"Legacy plaintext without length prefix";
        let legacy_encoded = STANDARD.encode(legacy_data);
        // decode() should fall back to raw format
        let decoded = decode(&legacy_encoded).unwrap();
        assert_eq!(legacy_data.as_slice(), decoded.as_slice());
    }
}
