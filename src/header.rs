use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::crypto::Algorithm;
use crate::hybrid::{self, EncapsulatedKeys, HybridPrivateKey, HybridPublicKey};

const MAGIC: &str = "CCRYPT";
const VERSION_PLAIN: u8 = 7;
const VERSION_ENCRYPTED: u8 = 8;

/// Argon2 key derivation parameters stored in header for forward compatibility
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    pub m_cost: u32, // Memory cost in KiB
    pub t_cost: u32, // Time cost (iterations)
    pub p_cost: u32, // Parallelism
}

// Argon2id defaults (stronger than argon2 crate defaults, per OWASP 2024)
const ARGON2_M_COST: u32 = 65536; // 64 MiB memory
const ARGON2_T_COST: u32 = 3; // 3 iterations
const ARGON2_P_COST: u32 = 4; // 4 parallel lanes

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost: ARGON2_M_COST,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
        }
    }
}

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
    #[error("Ciphertext hash mismatch - data may be corrupted or tampered")]
    CiphertextHashMismatch,
    #[error("Missing ciphertext hash - header created without integrity protection")]
    MissingCiphertextHash,
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

#[derive(Serialize, Deserialize)]
struct EncryptedPayload {
    algo_codes: String,
    salt: [u8; 32],
    #[serde(default)]
    seal: bool,
    #[serde(default)]
    argon2: Argon2Params,
}

#[derive(Debug, Clone)]
pub struct Header {
    pub algorithms: Vec<Algorithm>,
    pub salt: [u8; 32],
    pub locked: bool,
    pub ciphertext_hash: Option<[u8; 32]>,
    pub argon2_params: Argon2Params,
}

impl Header {
    /// Creates a header without ciphertext integrity hash.
    ///
    /// # Deprecated
    /// Use [`Header::with_ciphertext`] instead to ensure integrity protection.
    /// Headers created with this method will fail verification in `verify_ciphertext()`.
    #[deprecated(
        since = "0.2.2",
        note = "Use Header::with_ciphertext() for integrity protection"
    )]
    pub fn new(algorithms: Vec<Algorithm>, salt: [u8; 32], locked: bool) -> Self {
        Self {
            algorithms,
            salt,
            locked,
            ciphertext_hash: None,
            argon2_params: Argon2Params::default(),
        }
    }

    /// Creates a header with ciphertext integrity hash.
    ///
    /// The SHA-256 hash of the ciphertext is stored in the header and verified
    /// during decryption to detect tampering or corruption.
    pub fn with_ciphertext(
        algorithms: Vec<Algorithm>,
        salt: [u8; 32],
        locked: bool,
        ciphertext: &[u8],
    ) -> Self {
        let hash = Sha256::digest(ciphertext);
        Self {
            algorithms,
            salt,
            locked,
            ciphertext_hash: Some(hash.into()),
            argon2_params: Argon2Params::default(),
        }
    }

    #[must_use]
    pub fn algo_codes(&self) -> String {
        self.algorithms.iter().map(Algorithm::code).collect()
    }

    fn argon2_str(&self) -> String {
        format!(
            "{},{},{}",
            self.argon2_params.m_cost, self.argon2_params.t_cost, self.argon2_params.p_cost
        )
    }

    fn compute_hash_bytes(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.algo_codes().as_bytes());
        h.update(self.salt);
        h.update(self.argon2_str().as_bytes());
        if let Some(ct_hash) = &self.ciphertext_hash {
            h.update(ct_hash);
        }
        h.finalize().into()
    }

    fn compute_hash(&self) -> String {
        hex::encode(&self.compute_hash_bytes())
    }

    #[must_use]
    pub fn serialize(&self) -> String {
        let ct_hash_hex = self
            .ciphertext_hash
            .map(|h| hex::encode(&h))
            .unwrap_or_default();
        format!(
            "[{}|{}|{}|{}|{}|{}|{}]\n",
            MAGIC,
            VERSION_PLAIN,
            self.algo_codes(),
            hex::encode(&self.salt),
            self.argon2_str(),
            ct_hash_hex,
            self.compute_hash()
        )
    }

    pub fn serialize_encrypted(&self, recipient: &HybridPublicKey) -> Result<String, HeaderError> {
        let payload = serde_json::to_string(&EncryptedPayload {
            algo_codes: self.algo_codes(),
            salt: self.salt,
            seal: self.locked,
            argon2: self.argon2_params,
        })
        .map_err(|e| HeaderError::JsonError(e.to_string()))?;

        let (encap, ct) = hybrid::encrypt(payload.as_bytes(), recipient)?;
        let encap_b64 = B64.encode(
            serde_json::to_string(&encap).map_err(|e| HeaderError::JsonError(e.to_string()))?,
        );
        let ct_b64 = B64.encode(&ct);
        let ct_hash_hex = self
            .ciphertext_hash
            .map(|h| hex::encode(&h))
            .unwrap_or_default();

        let mut h = Sha256::new();
        h.update(&encap_b64);
        h.update(&ct_b64);
        h.update(&ct_hash_hex);

        Ok(format!(
            "[{}|{}|E|{}|{}|{}|{}]\n",
            MAGIC,
            VERSION_ENCRYPTED,
            encap_b64,
            ct_b64,
            ct_hash_hex,
            hex::encode(&h.finalize())
        ))
    }

    pub fn parse(data: &[u8]) -> Result<(Self, &[u8]), HeaderError> {
        let (parts, remaining) = parse_header_line(data)?;
        if parts[0] != MAGIC {
            return Err(HeaderError::InvalidMagic);
        }

        match parts[1]
            .parse::<u8>()
            .map_err(|_| HeaderError::InvalidFormat)?
        {
            VERSION_PLAIN if parts.len() == 7 => {
                let algorithms = parse_algos(parts[2])?;
                let salt = parse_salt(parts[3])?;
                let argon2_params = parse_argon2(parts[4])?;
                let ciphertext_hash = parse_hash(parts[5])?;
                let header = Self {
                    algorithms,
                    salt,
                    locked: false,
                    ciphertext_hash: Some(ciphertext_hash),
                    argon2_params,
                };
                let provided_hash =
                    hex::decode(parts[6]).map_err(|_| HeaderError::InvalidFormat)?;
                let expected_hash = header.compute_hash_bytes();
                if provided_hash.len() != 32
                    || provided_hash.as_slice().ct_eq(&expected_hash).unwrap_u8() != 1
                {
                    return Err(HeaderError::HashMismatch);
                }
                Ok((header, remaining))
            }
            VERSION_ENCRYPTED => Err(HeaderError::EncryptedHeader),
            v => Err(HeaderError::UnsupportedVersion(v)),
        }
    }

    /// Verify that the ciphertext matches the hash stored in the header.
    ///
    /// # Errors
    /// - `MissingCiphertextHash` if header was created without integrity protection
    /// - `CiphertextHashMismatch` if ciphertext has been tampered with or corrupted
    pub fn verify_ciphertext(&self, ciphertext: &[u8]) -> Result<(), HeaderError> {
        let expected = self
            .ciphertext_hash
            .ok_or(HeaderError::MissingCiphertextHash)?;
        let actual: [u8; 32] = Sha256::digest(ciphertext).into();
        if actual.ct_eq(&expected).unwrap_u8() != 1 {
            return Err(HeaderError::CiphertextHashMismatch);
        }
        Ok(())
    }

    pub fn parse_encrypted<'a>(
        data: &'a [u8],
        private_key: &HybridPrivateKey,
    ) -> Result<(Self, &'a [u8]), HeaderError> {
        let (parts, remaining) = parse_header_line(data)?;
        if parts[0] != MAGIC {
            return Err(HeaderError::InvalidMagic);
        }
        if parts.len() != 7 || parts[2] != "E" {
            return Err(HeaderError::InvalidFormat);
        }

        let version: u8 = parts[1].parse().map_err(|_| HeaderError::InvalidFormat)?;
        if version != VERSION_ENCRYPTED {
            return Err(HeaderError::UnsupportedVersion(version));
        }

        // Verify header hash (constant-time comparison)
        let mut h = Sha256::new();
        h.update(parts[3]);
        h.update(parts[4]);
        h.update(parts[5]);
        let expected_hash: [u8; 32] = h.finalize().into();
        let provided_hash = hex::decode(parts[6]).map_err(|_| HeaderError::InvalidFormat)?;
        if provided_hash.len() != 32
            || provided_hash.as_slice().ct_eq(&expected_hash).unwrap_u8() != 1
        {
            return Err(HeaderError::HashMismatch);
        }

        let encap: EncapsulatedKeys =
            serde_json::from_slice(&B64.decode(parts[3]).map_err(|_| HeaderError::Base64Error)?)
                .map_err(|e| HeaderError::JsonError(e.to_string()))?;

        let ct = B64.decode(parts[4]).map_err(|_| HeaderError::Base64Error)?;
        let payload: EncryptedPayload =
            serde_json::from_slice(&hybrid::decrypt(&encap, &ct, private_key)?)
                .map_err(|e| HeaderError::JsonError(e.to_string()))?;

        let ciphertext_hash = parse_hash(parts[5])?;
        Ok((
            Self {
                algorithms: parse_algos(&payload.algo_codes)?,
                salt: payload.salt,
                locked: payload.seal,
                ciphertext_hash: Some(ciphertext_hash),
                argon2_params: payload.argon2,
            },
            remaining,
        ))
    }

    #[must_use]
    pub fn is_encrypted(data: &[u8]) -> bool {
        parse_header_line(data)
            .map(|(p, _)| p.len() >= 3 && p[0] == MAGIC && p[1] == "8" && p[2] == "E")
            .unwrap_or(false)
    }
}

fn parse_header_line(data: &[u8]) -> Result<(Vec<&str>, &[u8]), HeaderError> {
    let end = data
        .iter()
        .position(|&b| b == b'\n')
        .ok_or(HeaderError::InvalidFormat)?;
    let s = std::str::from_utf8(&data[..end]).map_err(|_| HeaderError::InvalidFormat)?;
    let inner = s
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or(HeaderError::InvalidFormat)?;
    Ok((inner.split('|').collect(), &data[end + 1..]))
}

fn parse_algos(s: &str) -> Result<Vec<Algorithm>, HeaderError> {
    s.chars()
        .map(|c| Algorithm::from_code(c).ok_or(HeaderError::UnknownAlgorithm(c)))
        .collect()
}

fn parse_salt(s: &str) -> Result<[u8; 32], HeaderError> {
    let bytes = hex::decode(s).map_err(|_| HeaderError::InvalidFormat)?;
    bytes.try_into().map_err(|_| HeaderError::MissingSalt)
}

fn parse_hash(s: &str) -> Result<[u8; 32], HeaderError> {
    let bytes = hex::decode(s).map_err(|_| HeaderError::InvalidFormat)?;
    bytes.try_into().map_err(|_| HeaderError::InvalidFormat)
}

fn parse_argon2(s: &str) -> Result<Argon2Params, HeaderError> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() != 3 {
        return Err(HeaderError::InvalidFormat);
    }
    Ok(Argon2Params {
        m_cost: parts[0].parse().map_err(|_| HeaderError::InvalidFormat)?,
        t_cost: parts[1].parse().map_err(|_| HeaderError::InvalidFormat)?,
        p_cost: parts[2].parse().map_err(|_| HeaderError::InvalidFormat)?,
    })
}

/// Minimal hex encoding/decoding to avoid external dependency.
mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(bytes: &[u8]) -> String {
        let mut result = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            result.push(HEX_CHARS[(b >> 4) as usize] as char);
            result.push(HEX_CHARS[(b & 0xf) as usize] as char);
        }
        result
    }

    fn hex_digit(b: u8) -> Result<u8, ()> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(()),
        }
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if !s.len().is_multiple_of(2) {
            return Err(());
        }
        s.as_bytes()
            .chunks(2)
            .map(|c| Ok((hex_digit(c[0])? << 4) | hex_digit(c[1])?))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid::HybridKeypair;
    use rand::RngCore;

    fn random_salt() -> [u8; 32] {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        salt
    }

    #[test]
    fn test_header_roundtrip() {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        let ciphertext = b"encrypted data here";
        let header = Header::with_ciphertext(
            vec![
                Algorithm::Aes256,
                Algorithm::TripleDes,
                Algorithm::Twofish,
                Algorithm::Serpent,
            ],
            salt,
            false,
            ciphertext,
        );
        let mut full = header.serialize().into_bytes();
        full.extend_from_slice(ciphertext);
        let (parsed, remaining) = Header::parse(&full).unwrap();
        assert_eq!(parsed.algorithms, header.algorithms);
        assert_eq!(parsed.salt, header.salt);
        assert_eq!(remaining, ciphertext);
        // Verify ciphertext hash
        parsed.verify_ciphertext(remaining).unwrap();
    }

    #[test]
    fn test_encrypted_header_roundtrip() {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        let ciphertext = b"encrypted data here";
        let header = Header::with_ciphertext(
            vec![Algorithm::Aes256, Algorithm::ChaCha20Poly1305],
            salt,
            false,
            ciphertext,
        );
        let keypair = HybridKeypair::generate();
        let mut full = header
            .serialize_encrypted(&keypair.public)
            .unwrap()
            .into_bytes();
        full.extend_from_slice(ciphertext);
        assert!(Header::is_encrypted(&full));
        let (parsed, remaining) = Header::parse_encrypted(&full, &keypair.private).unwrap();
        assert_eq!(parsed.algorithms, header.algorithms);
        assert_eq!(parsed.salt, header.salt);
        assert_eq!(remaining, ciphertext);
        // Verify ciphertext hash
        parsed.verify_ciphertext(remaining).unwrap();
    }

    #[test]
    fn test_encrypted_header_with_seal() {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        let ciphertext = b"sealed data";
        let header = Header::with_ciphertext(vec![Algorithm::Aes256], salt, true, ciphertext);
        let keypair = HybridKeypair::generate();
        let mut full = header
            .serialize_encrypted(&keypair.public)
            .unwrap()
            .into_bytes();
        full.extend_from_slice(ciphertext);
        let (parsed, _) = Header::parse_encrypted(&full, &keypair.private).unwrap();
        assert!(parsed.locked);
    }

    #[test]
    fn test_algo_codes() {
        let header = Header::with_ciphertext(
            vec![Algorithm::Aes256, Algorithm::Serpent, Algorithm::Twofish],
            random_salt(),
            false,
            b"dummy",
        );
        assert_eq!(header.algo_codes(), "ASW");
    }

    #[test]
    fn test_hash_mismatch_detection() {
        let ciphertext = b"test data";
        let header = Header::with_ciphertext(vec![Algorithm::Aes256], random_salt(), false, ciphertext);
        let tampered = header.serialize().replace("|A|", "|S|");
        assert!(matches!(
            Header::parse(tampered.as_bytes()),
            Err(HeaderError::HashMismatch)
        ));
    }

    #[test]
    fn test_ciphertext_hash_mismatch() {
        let ciphertext = b"original data";
        let header = Header::with_ciphertext(vec![Algorithm::Aes256], random_salt(), false, ciphertext);
        let mut full = header.serialize().into_bytes();
        full.extend_from_slice(ciphertext);
        let (parsed, _) = Header::parse(&full).unwrap();
        // Should fail with tampered ciphertext
        let tampered = b"tampered data";
        assert!(matches!(
            parsed.verify_ciphertext(tampered),
            Err(HeaderError::CiphertextHashMismatch)
        ));
    }
}
