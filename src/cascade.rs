use argon2::Argon2;
use rand::RngCore;
use thiserror::Error;

use crate::crypto::{self, Algorithm, CryptoError};
use crate::encoder;
use crate::header::{Header, HeaderError};
use crate::hybrid::{HybridPrivateKey, HybridPublicKey};

#[derive(Error, Debug)]
pub enum CascadeError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Header error: {0}")]
    Header(#[from] HeaderError),
    #[error("Key derivation failed")]
    KeyDerivation,
    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("No algorithms specified")]
    NoAlgorithms,
    #[error("Encrypted header requires private key")]
    PrivateKeyRequired,
}

fn derive_key(password: &[u8], salt: &[u8], algo: Algorithm) -> Result<Vec<u8>, CascadeError> {
    let argon2 = Argon2::default();
    let mut full_salt = Vec::with_capacity(salt.len() + algo.salt_context().len());
    full_salt.extend_from_slice(salt);
    full_salt.extend_from_slice(algo.salt_context());

    let mut key = vec![0u8; algo.key_size()];
    argon2
        .hash_password_into(password, &full_salt, &mut key)
        .map_err(|_| CascadeError::KeyDerivation)?;
    Ok(key)
}

// Core encryption loop with optional progress callback
fn encrypt_layers<F>(data: &[u8], password: &[u8], algorithms: &[Algorithm], salt: &[u8], mut progress: F) -> Result<Vec<u8>, CascadeError>
where F: FnMut(usize, usize) {
    let total = algorithms.len();
    let mut current = encoder::encode(data).into_bytes();
    for (i, algo) in algorithms.iter().enumerate() {
        let key = derive_key(password, salt, *algo)?;
        current = crypto::encrypt(*algo, &key, &current)?;
        progress(i + 1, total);
    }
    Ok(current)
}

pub fn encrypt(data: &[u8], password: &[u8], algorithms: Vec<Algorithm>) -> Result<Vec<u8>, CascadeError> {
    encrypt_with_progress(data, password, algorithms, |_, _| {})
}

pub fn encrypt_with_progress<F>(data: &[u8], password: &[u8], algorithms: Vec<Algorithm>, progress: F) -> Result<Vec<u8>, CascadeError>
where F: FnMut(usize, usize) {
    if algorithms.is_empty() { return Err(CascadeError::NoAlgorithms); }
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    let encrypted = encrypt_layers(data, password, &algorithms, &salt, progress)?;
    let mut result = Header::new(algorithms, salt).serialize().into_bytes();
    result.extend(encrypted);
    Ok(result)
}

pub fn encrypt_protected(data: &[u8], password: &[u8], algorithms: Vec<Algorithm>, recipient_public: &HybridPublicKey) -> Result<Vec<u8>, CascadeError> {
    encrypt_protected_with_progress(data, password, algorithms, recipient_public, |_, _| {})
}

pub fn encrypt_protected_with_progress<F>(data: &[u8], password: &[u8], algorithms: Vec<Algorithm>, recipient_public: &HybridPublicKey, progress: F) -> Result<Vec<u8>, CascadeError>
where F: FnMut(usize, usize) {
    if algorithms.is_empty() { return Err(CascadeError::NoAlgorithms); }
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    let encrypted = encrypt_layers(data, password, &algorithms, &salt, progress)?;
    let mut result = Header::new(algorithms, salt).serialize_encrypted(recipient_public)?.into_bytes();
    result.extend(encrypted);
    Ok(result)
}

pub fn decrypt(data: &[u8], password: &[u8]) -> Result<Vec<u8>, CascadeError> {
    decrypt_with_progress(data, password, |_, _| {})
}

pub fn decrypt_with_progress<F>(data: &[u8], password: &[u8], progress: F) -> Result<Vec<u8>, CascadeError>
where F: FnMut(usize, usize) {
    if Header::is_encrypted(data) { return Err(CascadeError::PrivateKeyRequired); }
    let (header, encrypted_data) = Header::parse(data)?;
    decrypt_layers(&header, encrypted_data, password, progress)
}

pub fn decrypt_protected(data: &[u8], password: &[u8], private_key: &HybridPrivateKey) -> Result<Vec<u8>, CascadeError> {
    decrypt_protected_with_progress(data, password, private_key, |_, _| {})
}

pub fn decrypt_protected_with_progress<F>(data: &[u8], password: &[u8], private_key: &HybridPrivateKey, progress: F) -> Result<Vec<u8>, CascadeError>
where F: FnMut(usize, usize) {
    let (header, encrypted_data) = if Header::is_encrypted(data) {
        Header::parse_encrypted(data, private_key)?
    } else {
        Header::parse(data)?
    };
    decrypt_layers(&header, encrypted_data, password, progress)
}

fn decrypt_layers<F>(header: &Header, encrypted_data: &[u8], password: &[u8], mut progress: F) -> Result<Vec<u8>, CascadeError>
where F: FnMut(usize, usize) {
    if header.algorithms.is_empty() { return Err(CascadeError::NoAlgorithms); }
    let total = header.algorithms.len();
    let mut current = encrypted_data.to_vec();
    for (i, algo) in header.algorithms.iter().rev().enumerate() {
        let key = derive_key(password, &header.salt, *algo)?;
        current = crypto::decrypt(*algo, &key, &current)?;
        progress(i + 1, total);
    }
    let decoded_str = String::from_utf8(current).map_err(|_| CascadeError::Crypto(CryptoError::DecryptionFailed("Invalid UTF-8".into())))?;
    Ok(encoder::decode(&decoded_str)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid::HybridKeypair;

    #[test]
    fn test_single_algorithm() {
        let data = b"Hello, cascade-crypt!";
        let password = b"test-password";
        let encrypted = encrypt(data, password, vec![Algorithm::Aes256]).unwrap();
        let decrypted = decrypt(&encrypted, password).unwrap();
        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_full_cascade() {
        let data = b"Testing all four algorithms!";
        let password = b"strong-password-123";
        let encrypted = encrypt(
            data,
            password,
            vec![
                Algorithm::Aes256,
                Algorithm::TripleDes,
                Algorithm::Twofish,
                Algorithm::Serpent,
            ],
        )
        .unwrap();
        let decrypted = decrypt(&encrypted, password).unwrap();
        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_binary_data() {
        let data: Vec<u8> = (0..=255).collect();
        let password = b"binary-test";
        let encrypted = encrypt(&data, password, vec![Algorithm::Serpent, Algorithm::Aes256]).unwrap();
        let decrypted = decrypt(&encrypted, password).unwrap();
        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_wrong_password() {
        let data = b"Secret data";
        let encrypted = encrypt(data, b"correct", vec![Algorithm::Aes256]).unwrap();
        assert!(decrypt(&encrypted, b"wrong").is_err());
    }

    #[test]
    fn test_protected_encrypt_decrypt() {
        let data = b"Secret data with protected header";
        let password = b"test-password";
        let keypair = HybridKeypair::generate();

        let encrypted = encrypt_protected(
            data,
            password,
            vec![Algorithm::Aes256, Algorithm::ChaCha20Poly1305],
            &keypair.public,
        )
        .unwrap();

        assert!(Header::is_encrypted(&encrypted));
        let decrypted = decrypt_protected(&encrypted, password, &keypair.private).unwrap();
        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_protected_requires_private_key() {
        let data = b"Secret data";
        let keypair = HybridKeypair::generate();
        let encrypted = encrypt_protected(data, b"pass", vec![Algorithm::Aes256], &keypair.public).unwrap();
        assert!(matches!(decrypt(&encrypted, b"pass"), Err(CascadeError::PrivateKeyRequired)));
    }
}
