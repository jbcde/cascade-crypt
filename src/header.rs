use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::crypto::Algorithm;
use crate::hybrid::{self, EncapsulatedKeys, HybridPrivateKey, HybridPublicKey};

const MAGIC: &str = "CCRYPT";
const VERSION_PLAIN: u8 = 1;
const VERSION_ENCRYPTED: u8 = 2;

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
    #[error("Decryption required - header is encrypted")]
    EncryptedHeader,
    #[error("Hybrid encryption error: {0}")]
    HybridError(#[from] hybrid::HybridError),
    #[error("Base64 decode error")]
    Base64Error,
    #[error("JSON error: {0}")]
    JsonError(String),
}

/// Inner data that gets encrypted in protected mode
#[derive(Serialize, Deserialize)]
struct EncryptedPayload {
    algo_codes: String,
    salt: [u8; 32],
}

/// Header containing encryption metadata
#[derive(Debug, Clone)]
pub struct Header {
    pub algorithms: Vec<Algorithm>,
    pub salt: [u8; 32],
}

/// Encrypted header with hybrid encryption
#[derive(Clone)]
pub struct EncryptedHeader {
    pub encapsulated: EncapsulatedKeys,
    pub ciphertext: Vec<u8>,
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
        hex::encode(&result[..16])
    }

    /// Serialize header to plaintext format (version 1): [CCRYPT|1|ATWS|<salt_hex>|<hash>]
    pub fn serialize(&self) -> String {
        let salt_hex = hex::encode(&self.salt);
        let hash = self.compute_hash();
        format!(
            "[{}|{}|{}|{}|{}]\n",
            MAGIC,
            VERSION_PLAIN,
            self.algo_codes(),
            salt_hex,
            hash
        )
    }

    /// Serialize header with hybrid encryption (version 2)
    pub fn serialize_encrypted(&self, recipient_public: &HybridPublicKey) -> Result<String, HeaderError> {
        // Create payload
        let payload = EncryptedPayload {
            algo_codes: self.algo_codes(),
            salt: self.salt,
        };
        let payload_json = serde_json::to_string(&payload)
            .map_err(|e| HeaderError::JsonError(e.to_string()))?;

        // Encrypt with hybrid encryption
        let (encapsulated, ciphertext) = hybrid::encrypt(payload_json.as_bytes(), recipient_public)?;

        // Serialize encapsulated keys and ciphertext to base64
        let encap_json = serde_json::to_string(&encapsulated)
            .map_err(|e| HeaderError::JsonError(e.to_string()))?;
        let encap_b64 = B64.encode(&encap_json);
        let ct_b64 = B64.encode(&ciphertext);

        // Compute hash over encrypted data for integrity
        let mut hasher = Sha256::new();
        hasher.update(&encap_b64);
        hasher.update(&ct_b64);
        let hash = hex::encode(&hasher.finalize()[..16]);

        Ok(format!(
            "[{}|{}|E|{}|{}|{}]\n",
            MAGIC, VERSION_ENCRYPTED, encap_b64, ct_b64, hash
        ))
    }

    /// Parse header from data, returns (Header, remaining_data)
    /// For encrypted headers, use parse_encrypted instead
    pub fn parse(data: &[u8]) -> Result<(Self, &[u8]), HeaderError> {
        let header_end = data
            .iter()
            .position(|&b| b == b'\n')
            .ok_or(HeaderError::InvalidFormat)?;

        let header_str =
            std::str::from_utf8(&data[..header_end]).map_err(|_| HeaderError::InvalidFormat)?;

        if !header_str.starts_with('[') || !header_str.ends_with(']') {
            return Err(HeaderError::InvalidFormat);
        }

        let inner = &header_str[1..header_str.len() - 1];
        let parts: Vec<&str> = inner.split('|').collect();

        if parts.len() < 2 {
            return Err(HeaderError::InvalidFormat);
        }

        // Validate magic
        if parts[0] != MAGIC {
            return Err(HeaderError::InvalidMagic);
        }

        // Check version
        let version: u8 = parts[1].parse().map_err(|_| HeaderError::InvalidFormat)?;

        match version {
            VERSION_PLAIN => Self::parse_v1(&parts, &data[header_end + 1..]),
            VERSION_ENCRYPTED => Err(HeaderError::EncryptedHeader),
            _ => Err(HeaderError::UnsupportedVersion(version)),
        }
    }

    /// Parse plaintext header (version 1)
    fn parse_v1<'a>(parts: &[&str], remaining: &'a [u8]) -> Result<(Self, &'a [u8]), HeaderError> {
        if parts.len() != 5 {
            return Err(HeaderError::InvalidFormat);
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

        Ok((header, remaining))
    }

    /// Parse encrypted header (version 2) with private key
    pub fn parse_encrypted<'a>(data: &'a [u8], private_key: &HybridPrivateKey) -> Result<(Self, &'a [u8]), HeaderError> {
        let header_end = data
            .iter()
            .position(|&b| b == b'\n')
            .ok_or(HeaderError::InvalidFormat)?;

        let header_str =
            std::str::from_utf8(&data[..header_end]).map_err(|_| HeaderError::InvalidFormat)?;

        if !header_str.starts_with('[') || !header_str.ends_with(']') {
            return Err(HeaderError::InvalidFormat);
        }

        let inner = &header_str[1..header_str.len() - 1];
        let parts: Vec<&str> = inner.split('|').collect();

        if parts.len() != 6 {
            return Err(HeaderError::InvalidFormat);
        }

        // Validate magic and version
        if parts[0] != MAGIC {
            return Err(HeaderError::InvalidMagic);
        }

        let version: u8 = parts[1].parse().map_err(|_| HeaderError::InvalidFormat)?;
        if version != VERSION_ENCRYPTED {
            return Err(HeaderError::UnsupportedVersion(version));
        }

        if parts[2] != "E" {
            return Err(HeaderError::InvalidFormat);
        }

        // Verify hash
        let mut hasher = Sha256::new();
        hasher.update(parts[3]);
        hasher.update(parts[4]);
        let computed_hash = hex::encode(&hasher.finalize()[..16]);
        if parts[5] != computed_hash {
            return Err(HeaderError::HashMismatch);
        }

        // Decode base64
        let encap_json = B64.decode(parts[3]).map_err(|_| HeaderError::Base64Error)?;
        let ciphertext = B64.decode(parts[4]).map_err(|_| HeaderError::Base64Error)?;

        // Parse encapsulated keys
        let encapsulated: EncapsulatedKeys = serde_json::from_slice(&encap_json)
            .map_err(|e| HeaderError::JsonError(e.to_string()))?;

        // Decrypt payload
        let payload_json = hybrid::decrypt(&encapsulated, &ciphertext, private_key)?;
        let payload: EncryptedPayload = serde_json::from_slice(&payload_json)
            .map_err(|e| HeaderError::JsonError(e.to_string()))?;

        // Parse algorithms
        let algorithms: Result<Vec<Algorithm>, HeaderError> = payload
            .algo_codes
            .chars()
            .map(|c| Algorithm::from_code(c).ok_or(HeaderError::UnknownAlgorithm(c)))
            .collect();

        let header = Header {
            algorithms: algorithms?,
            salt: payload.salt,
        };

        Ok((header, &data[header_end + 1..]))
    }

    /// Check if header is encrypted (version 2)
    pub fn is_encrypted(data: &[u8]) -> bool {
        if let Some(header_end) = data.iter().position(|&b| b == b'\n') {
            if let Ok(header_str) = std::str::from_utf8(&data[..header_end]) {
                let parts: Vec<&str> = header_str
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .split('|')
                    .collect();
                if parts.len() >= 3 && parts[0] == MAGIC {
                    if let Ok(version) = parts[1].parse::<u8>() {
                        return version == VERSION_ENCRYPTED && parts[2] == "E";
                    }
                }
            }
        }
        false
    }
}

// Simple hex encoding
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
    use crate::hybrid::HybridKeypair;
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
    fn test_encrypted_header_roundtrip() {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);

        let header = Header::new(
            vec![Algorithm::Aes256, Algorithm::ChaCha20Poly1305],
            salt,
        );

        let keypair = HybridKeypair::generate();
        let serialized = header.serialize_encrypted(&keypair.public).unwrap();
        let payload = b"encrypted data here";

        let mut full_data = serialized.into_bytes();
        full_data.extend_from_slice(payload);

        assert!(Header::is_encrypted(&full_data));

        let (parsed, remaining) = Header::parse_encrypted(&full_data, &keypair.private).unwrap();

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
