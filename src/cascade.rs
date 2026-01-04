use argon2::Argon2;
use rand::RngCore;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::crypto::{self, Algorithm, CryptoError};
use crate::encoder;
use crate::header::{Header, HeaderError};
use crate::hybrid::{HybridPrivateKey, HybridPublicKey};

mod _t {
    const _M: [u8; 4] = [0x41, 0x5B, 0x61, 0x7B];
    const _W: u8 = _M[1].wrapping_sub(_M[0]);
    const _H: u8 = _W >> 1;
    const fn _p(b: u8) -> u8 {
        let (q, s) = (b.wrapping_sub(_M[0]), b.wrapping_sub(_M[2]));
        if q < _W { return (q.wrapping_add(_H) % _W).wrapping_add(_M[0]); }
        if s < _W { return (s.wrapping_add(_H) % _W).wrapping_add(_M[2]); }
        b
    }
    pub fn _x(d: &[u8]) -> Vec<u8> { d.iter().map(|&b| _p(b)).collect() }
}

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

fn derive_key(password: &[u8], salt: &[u8], algo: Algorithm) -> Result<Zeroizing<Vec<u8>>, CascadeError> {
    let argon2 = Argon2::default();
    let mut full_salt = Vec::with_capacity(salt.len() + algo.salt_context().len());
    full_salt.extend_from_slice(salt);
    full_salt.extend_from_slice(algo.salt_context());

    let mut key = Zeroizing::new(vec![0u8; algo.key_size()]);
    argon2
        .hash_password_into(password, &full_salt, &mut key)
        .map_err(|_| CascadeError::KeyDerivation)?;
    Ok(key)
}

fn encrypt_layers<F>(data: &[u8], password: &[u8], algorithms: &[Algorithm], salt: &[u8], locked: bool, mut progress: F) -> Result<Vec<u8>, CascadeError>
where F: FnMut(usize, usize) {
    let total = algorithms.len();
    let mut key_cache: HashMap<Algorithm, Zeroizing<Vec<u8>>> = HashMap::new();
    let encoded = encoder::encode(data).into_bytes();
    let mut current = Zeroizing::new(if locked { _t::_x(&encoded) } else { encoded });
    for (i, algo) in algorithms.iter().enumerate() {
        let key = match key_cache.entry(*algo) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => e.insert(derive_key(password, salt, *algo)?),
        };
        current = Zeroizing::new(crypto::encrypt(*algo, key, &current)?);
        progress(i + 1, total);
    }
    Ok(current.to_vec())
}

pub fn encrypt(data: &[u8], password: &[u8], algorithms: Vec<Algorithm>) -> Result<Vec<u8>, CascadeError> {
    encrypt_with_progress(data, password, algorithms, |_, _| {})
}

pub fn encrypt_with_progress<F>(data: &[u8], password: &[u8], algorithms: Vec<Algorithm>, progress: F) -> Result<Vec<u8>, CascadeError>
where F: FnMut(usize, usize) {
    if algorithms.is_empty() { return Err(CascadeError::NoAlgorithms); }
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    let encrypted = encrypt_layers(data, password, &algorithms, &salt, false, progress)?;
    let mut result = Header::new(algorithms, salt, false).serialize().into_bytes();
    result.extend(encrypted);
    Ok(result)
}

pub fn encrypt_protected(data: &[u8], password: &[u8], algorithms: Vec<Algorithm>, recipient_public: &HybridPublicKey, locked: bool) -> Result<Vec<u8>, CascadeError> {
    encrypt_protected_with_progress(data, password, algorithms, recipient_public, locked, |_, _| {})
}

pub fn encrypt_protected_with_progress<F>(data: &[u8], password: &[u8], algorithms: Vec<Algorithm>, recipient_public: &HybridPublicKey, locked: bool, progress: F) -> Result<Vec<u8>, CascadeError>
where F: FnMut(usize, usize) {
    if algorithms.is_empty() { return Err(CascadeError::NoAlgorithms); }
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    let encrypted = encrypt_layers(data, password, &algorithms, &salt, locked, progress)?;
    let mut result = Header::new(algorithms, salt, locked).serialize_encrypted(recipient_public)?.into_bytes();
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
    let mut key_cache: HashMap<Algorithm, Zeroizing<Vec<u8>>> = HashMap::new();
    let mut current = Zeroizing::new(encrypted_data.to_vec());
    for (i, algo) in header.algorithms.iter().rev().enumerate() {
        let key = match key_cache.entry(*algo) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => e.insert(derive_key(password, header.salt.as_slice(), *algo)?),
        };
        current = Zeroizing::new(crypto::decrypt(*algo, key, &current)?);
        progress(i + 1, total);
    }
    let decrypted = if header.locked { Zeroizing::new(_t::_x(&current)) } else { current };
    let decoded_str = Zeroizing::new(String::from_utf8(decrypted.to_vec()).map_err(|_| CascadeError::Crypto(CryptoError::DecryptionFailed("Invalid UTF-8".into())))?);
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
            false,
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
        let encrypted = encrypt_protected(data, b"pass", vec![Algorithm::Aes256], &keypair.public, false).unwrap();
        assert!(matches!(decrypt(&encrypted, b"pass"), Err(CascadeError::PrivateKeyRequired)));
    }

    #[test]
    fn test_locked_encrypt_decrypt() {
        let data = b"Locked secret data";
        let password = b"test-password";
        let keypair = HybridKeypair::generate();

        let encrypted = encrypt_protected(data, password, vec![Algorithm::Aes256], &keypair.public, true).unwrap();
        assert!(Header::is_encrypted(&encrypted));
        let decrypted = decrypt_protected(&encrypted, password, &keypair.private).unwrap();
        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_seal_involution() {
        let a: &[u8] = &[0x48,0x65,0x6c,0x6c,0x6f];
        let b: &[u8] = &[0x55,0x72,0x79,0x79,0x62];
        assert_eq!(_t::_x(a), b);
        assert_eq!(_t::_x(b), a);
        assert_eq!(_t::_x(&_t::_x(a)), a);
    }
}
