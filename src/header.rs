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

#[derive(Serialize, Deserialize)]
struct EncryptedPayload {
    algo_codes: String,
    salt: [u8; 32],
    #[serde(default)]
    seal: bool,
}

#[derive(Debug, Clone)]
pub struct Header {
    pub algorithms: Vec<Algorithm>,
    pub salt: [u8; 32],
    pub locked: bool,
}

impl Header {
    pub fn new(algorithms: Vec<Algorithm>, salt: [u8; 32], locked: bool) -> Self {
        Self { algorithms, salt, locked }
    }

    #[must_use]
    pub fn algo_codes(&self) -> String {
        self.algorithms.iter().map(Algorithm::code).collect()
    }

    fn compute_hash(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.algo_codes().as_bytes());
        h.update(self.salt);
        hex::encode(&h.finalize()[..16])
    }

    #[must_use]
    pub fn serialize(&self) -> String {
        format!(
            "[{}|{}|{}|{}|{}]\n",
            MAGIC, VERSION_PLAIN, self.algo_codes(), hex::encode(&self.salt), self.compute_hash()
        )
    }

    pub fn serialize_encrypted(&self, recipient: &HybridPublicKey) -> Result<String, HeaderError> {
        let payload = serde_json::to_string(&EncryptedPayload {
            algo_codes: self.algo_codes(),
            salt: self.salt,
            seal: self.locked,
        }).map_err(|e| HeaderError::JsonError(e.to_string()))?;

        let (encap, ct) = hybrid::encrypt(payload.as_bytes(), recipient)?;
        let encap_b64 = B64.encode(serde_json::to_string(&encap)
            .map_err(|e| HeaderError::JsonError(e.to_string()))?);
        let ct_b64 = B64.encode(&ct);

        let mut h = Sha256::new();
        h.update(&encap_b64);
        h.update(&ct_b64);

        Ok(format!("[{}|{}|E|{}|{}|{}]\n", MAGIC, VERSION_ENCRYPTED, encap_b64, ct_b64, hex::encode(&h.finalize()[..16])))
    }

    pub fn parse(data: &[u8]) -> Result<(Self, &[u8]), HeaderError> {
        let (parts, remaining) = parse_header_line(data)?;
        if parts[0] != MAGIC { return Err(HeaderError::InvalidMagic); }

        match parts[1].parse::<u8>().map_err(|_| HeaderError::InvalidFormat)? {
            VERSION_PLAIN if parts.len() == 5 => {
                let algorithms = parse_algos(parts[2])?;
                let salt = parse_salt(parts[3])?;
                let header = Self { algorithms, salt, locked: false };
                if parts[4] != header.compute_hash() {
                    return Err(HeaderError::HashMismatch);
                }
                Ok((header, remaining))
            }
            VERSION_ENCRYPTED => Err(HeaderError::EncryptedHeader),
            v => Err(HeaderError::UnsupportedVersion(v)),
        }
    }

    pub fn parse_encrypted<'a>(data: &'a [u8], private_key: &HybridPrivateKey) -> Result<(Self, &'a [u8]), HeaderError> {
        let (parts, remaining) = parse_header_line(data)?;
        if parts[0] != MAGIC { return Err(HeaderError::InvalidMagic); }
        if parts.len() != 6 || parts[2] != "E" { return Err(HeaderError::InvalidFormat); }

        let version: u8 = parts[1].parse().map_err(|_| HeaderError::InvalidFormat)?;
        if version != VERSION_ENCRYPTED { return Err(HeaderError::UnsupportedVersion(version)); }

        // Verify hash
        let mut h = Sha256::new();
        h.update(parts[3]);
        h.update(parts[4]);
        if parts[5] != hex::encode(&h.finalize()[..16]) {
            return Err(HeaderError::HashMismatch);
        }

        let encap: EncapsulatedKeys = serde_json::from_slice(
            &B64.decode(parts[3]).map_err(|_| HeaderError::Base64Error)?
        ).map_err(|e| HeaderError::JsonError(e.to_string()))?;

        let ct = B64.decode(parts[4]).map_err(|_| HeaderError::Base64Error)?;
        let payload: EncryptedPayload = serde_json::from_slice(
            &hybrid::decrypt(&encap, &ct, private_key)?
        ).map_err(|e| HeaderError::JsonError(e.to_string()))?;

        Ok((Self { algorithms: parse_algos(&payload.algo_codes)?, salt: payload.salt, locked: payload.seal }, remaining))
    }

    #[must_use]
    pub fn is_encrypted(data: &[u8]) -> bool {
        parse_header_line(data)
            .map(|(p, _)| p.len() >= 3 && p[0] == MAGIC && p[1] == "2" && p[2] == "E")
            .unwrap_or(false)
    }
}

fn parse_header_line(data: &[u8]) -> Result<(Vec<&str>, &[u8]), HeaderError> {
    let end = data.iter().position(|&b| b == b'\n').ok_or(HeaderError::InvalidFormat)?;
    let s = std::str::from_utf8(&data[..end]).map_err(|_| HeaderError::InvalidFormat)?;
    let inner = s.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or(HeaderError::InvalidFormat)?;
    Ok((inner.split('|').collect(), &data[end + 1..]))
}

fn parse_algos(s: &str) -> Result<Vec<Algorithm>, HeaderError> {
    s.chars().map(|c| Algorithm::from_code(c).ok_or(HeaderError::UnknownAlgorithm(c))).collect()
}

fn parse_salt(s: &str) -> Result<[u8; 32], HeaderError> {
    let bytes = hex::decode(s).map_err(|_| HeaderError::InvalidFormat)?;
    bytes.try_into().map_err(|_| HeaderError::MissingSalt)
}

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
        if s.len() % 2 != 0 { return Err(()); }
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

    #[test]
    fn test_header_roundtrip() {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        let header = Header::new(vec![Algorithm::Aes256, Algorithm::TripleDes, Algorithm::Twofish, Algorithm::Serpent], salt, false);
        let mut full = header.serialize().into_bytes();
        full.extend_from_slice(b"encrypted data here");
        let (parsed, remaining) = Header::parse(&full).unwrap();
        assert_eq!(parsed.algorithms, header.algorithms);
        assert_eq!(parsed.salt, header.salt);
        assert_eq!(remaining, b"encrypted data here");
    }

    #[test]
    fn test_encrypted_header_roundtrip() {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        let header = Header::new(vec![Algorithm::Aes256, Algorithm::ChaCha20Poly1305], salt, false);
        let keypair = HybridKeypair::generate();
        let mut full = header.serialize_encrypted(&keypair.public).unwrap().into_bytes();
        full.extend_from_slice(b"encrypted data here");
        assert!(Header::is_encrypted(&full));
        let (parsed, remaining) = Header::parse_encrypted(&full, &keypair.private).unwrap();
        assert_eq!(parsed.algorithms, header.algorithms);
        assert_eq!(parsed.salt, header.salt);
        assert_eq!(remaining, b"encrypted data here");
    }

    #[test]
    fn test_encrypted_header_with_seal() {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        let header = Header::new(vec![Algorithm::Aes256], salt, true);
        let keypair = HybridKeypair::generate();
        let full = header.serialize_encrypted(&keypair.public).unwrap();
        let (parsed, _) = Header::parse_encrypted(full.as_bytes(), &keypair.private).unwrap();
        assert!(parsed.locked);
    }

    #[test]
    fn test_algo_codes() {
        let header = Header::new(vec![Algorithm::Aes256, Algorithm::Serpent, Algorithm::Twofish], [0u8; 32], false);
        assert_eq!(header.algo_codes(), "ASW");
    }

    #[test]
    fn test_hash_mismatch_detection() {
        let header = Header::new(vec![Algorithm::Aes256], [0u8; 32], false);
        let tampered = header.serialize().replace("|A|", "|S|");
        assert!(matches!(Header::parse(tampered.as_bytes()), Err(HeaderError::HashMismatch)));
    }
}
