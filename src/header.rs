use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::crypto::Algorithm;

const MAGIC: &str = "CCRYPT";
const VERSION: u8 = 1;

#[derive(Error, Debug)]
pub enum HeaderError {
    #[error("Invalid header format")]
    InvalidFormat,
    #[error("Invalid magic bytes")]
    InvalidMagic,
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u8),
    #[error("Unknown algorithm code: {0}")]
    UnknownAlgorithm(char),
    #[error("Hash mismatch - header may be corrupted")]
    HashMismatch,
    #[error("Missing salt")]
    MissingSalt,
}

/// Header containing encryption metadata
#[derive(Debug, Clone)]
pub struct Header {
    pub algorithms: Vec<Algorithm>,
    pub salt: [u8; 32], // Master salt for key derivation
}

impl Header {
    pub fn new(algorithms: Vec<Algorithm>, salt: [u8; 32]) -> Self {
        Self { algorithms, salt }
    }

    /// Get algorithm codes as a string (e.g., "ATWS")
    pub fn algo_codes(&self) -> String {
        self.algorithms.iter().map(|a| a.code()).collect()
    }

    /// Compute SHA-256 hash of algorithm codes + salt
    fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.algo_codes().as_bytes());
        hasher.update(&self.salt);
        let result = hasher.finalize();
        hex::encode(&result[..16]) // Use first 16 bytes (32 hex chars) for brevity
    }

    /// Serialize header to string format: [CCRYPT|1|ATWS|<salt_hex>|<hash>]
    pub fn serialize(&self) -> String {
        let salt_hex = hex::encode(&self.salt);
        let hash = self.compute_hash();
        format!(
            "[{}|{}|{}|{}|{}]\n",
            MAGIC,
            VERSION,
            self.algo_codes(),
            salt_hex,
            hash
        )
    }

    /// Parse header from string, returns (Header, remaining_data)
    pub fn parse(data: &[u8]) -> Result<(Self, &[u8]), HeaderError> {
        // Find header end
        let header_end = data
            .iter()
            .position(|&b| b == b'\n')
            .ok_or(HeaderError::InvalidFormat)?;

        let header_str =
            std::str::from_utf8(&data[..header_end]).map_err(|_| HeaderError::InvalidFormat)?;

        // Validate brackets
        if !header_str.starts_with('[') || !header_str.ends_with(']') {
            return Err(HeaderError::InvalidFormat);
        }

        let inner = &header_str[1..header_str.len() - 1];
        let parts: Vec<&str> = inner.split('|').collect();

        if parts.len() != 5 {
            return Err(HeaderError::InvalidFormat);
        }

        // Validate magic
        if parts[0] != MAGIC {
            return Err(HeaderError::InvalidMagic);
        }

        // Validate version
        let version: u8 = parts[1].parse().map_err(|_| HeaderError::InvalidFormat)?;
        if version != VERSION {
            return Err(HeaderError::UnsupportedVersion(version));
        }

        // Parse algorithms
        let algorithms: Result<Vec<Algorithm>, HeaderError> = parts[2]
            .chars()
            .map(|c| Algorithm::from_code(c).ok_or(HeaderError::UnknownAlgorithm(c)))
            .collect();
        let algorithms = algorithms?;

        // Parse salt
        let salt_bytes = hex::decode(parts[3]).map_err(|_| HeaderError::InvalidFormat)?;
        if salt_bytes.len() != 32 {
            return Err(HeaderError::MissingSalt);
        }
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&salt_bytes);

        // Verify hash
        let stored_hash = parts[4];
        let header = Self { algorithms, salt };
        let computed_hash = header.compute_hash();

        if stored_hash != computed_hash {
            return Err(HeaderError::HashMismatch);
        }

        // Return header and remaining data (after newline)
        Ok((header, &data[header_end + 1..]))
    }
}

// Simple hex encoding (to avoid adding another dependency)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if s.len() % 2 != 0 {
            return Err(());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn test_header_roundtrip() {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);

        let header = Header::new(
            vec![
                Algorithm::Aes256,
                Algorithm::TripleDes,
                Algorithm::Twofish,
                Algorithm::Serpent,
            ],
            salt,
        );

        let serialized = header.serialize();
        let payload = b"encrypted data here";

        let mut full_data = serialized.into_bytes();
        full_data.extend_from_slice(payload);

        let (parsed, remaining) = Header::parse(&full_data).unwrap();

        assert_eq!(parsed.algorithms, header.algorithms);
        assert_eq!(parsed.salt, header.salt);
        assert_eq!(remaining, payload);
    }

    #[test]
    fn test_algo_codes() {
        let salt = [0u8; 32];
        let header = Header::new(
            vec![Algorithm::Aes256, Algorithm::Serpent, Algorithm::Twofish],
            salt,
        );
        assert_eq!(header.algo_codes(), "ASW");
    }

    #[test]
    fn test_hash_mismatch_detection() {
        let salt = [0u8; 32];
        let header = Header::new(vec![Algorithm::Aes256], salt);
        let mut serialized = header.serialize();

        // Tamper with the algorithm code
        serialized = serialized.replace("|A|", "|S|");

        let result = Header::parse(serialized.as_bytes());
        assert!(matches!(result, Err(HeaderError::HashMismatch)));
    }
}
