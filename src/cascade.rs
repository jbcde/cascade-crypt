use argon2::Argon2;
use rand::Rng;
use rayon::prelude::*;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::buffer::{should_switch_to_disk, BufferMode, LayerBuffer, ProcessError};
use crate::crypto::{self, Algorithm, CryptoError};
use crate::encoder;
use crate::header::{Argon2Params, Header, HeaderError};
use crate::hybrid::{HybridPrivateKey, HybridPublicKey};

mod _t {
    const _C: [u8; 4] = [0x9E, 0x84, 0xBE, 0xA4];
    const fn _u(i: usize) -> u8 {
        _C[i] ^ 0xDF
    }
    const fn _w() -> u8 {
        _u(1).wrapping_sub(_u(0))
    }
    const fn _r() -> u8 {
        _w() >> 1
    }
    #[inline(never)]
    fn _g(b: u8, lo: u8) -> u8 {
        let d = b.wrapping_sub(lo);
        if d >= _w() {
            return b;
        }
        lo.wrapping_add((d.wrapping_add(_r())) % _w())
    }
    fn _f(b: u8) -> u8 {
        let t = _g(b, _u(0));
        if t != b {
            t
        } else {
            _g(b, _u(2))
        }
    }
    pub fn _x(d: &[u8]) -> Vec<u8> {
        d.iter().map(|&b| _f(b)).collect()
    }
}

#[derive(Error, Debug)]
pub enum CascadeError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Header error: {0}")]
    Header(#[from] HeaderError),
    #[error("Key derivation failed")]
    KeyDerivation,
    #[error("No algorithms specified")]
    NoAlgorithms,
    #[error("Encrypted header requires private key")]
    PrivateKeyRequired,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<ProcessError<CryptoError>> for CascadeError {
    fn from(err: ProcessError<CryptoError>) -> Self {
        match err {
            ProcessError::Io(e) => CascadeError::Io(e),
            ProcessError::Crypto(e) => CascadeError::Crypto(e),
        }
    }
}

pub(crate) fn derive_key(
    password: &[u8],
    salt: &[u8],
    algo: Algorithm,
    layer: usize,
    params: &Argon2Params,
) -> Result<crate::memlock::LockedVec, CascadeError> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(params.m_cost, params.t_cost, params.p_cost, None)
            .map_err(|_| CascadeError::KeyDerivation)?,
    );
    let mut full_salt = Vec::with_capacity(salt.len() + algo.salt_context().len() + 8);
    full_salt.extend_from_slice(salt);
    full_salt.extend_from_slice(algo.salt_context());
    full_salt.extend_from_slice(&(layer as u64).to_le_bytes());

    let mut key = vec![0u8; algo.key_size()];
    argon2
        .hash_password_into(password, &full_salt, &mut key)
        .map_err(|_| CascadeError::KeyDerivation)?;

    // LockedVec: mlocks the memory, zeroizes on drop, munlocks on drop
    Ok(crate::memlock::LockedVec::new(key))
}

/// Derive keys for each layer in parallel (unique key per layer position)
pub(crate) fn derive_keys_parallel(
    password: &[u8],
    salt: &[u8],
    algorithms: &[Algorithm],
    params: &Argon2Params,
) -> Result<Vec<crate::memlock::LockedVec>, CascadeError> {
    algorithms
        .par_iter()
        .enumerate()
        .map(|(i, algo)| derive_key(password, salt, *algo, i, params))
        .collect()
}

pub(crate) fn encrypt_layers<F>(
    data: &[u8],
    password: &[u8],
    algorithms: &[Algorithm],
    salt: &[u8],
    locked: bool,
    buffer_mode: BufferMode,
    mut progress: F,
) -> Result<Vec<u8>, CascadeError>
where
    F: FnMut(usize, usize),
{
    let total = algorithms.len();
    let keys = derive_keys_parallel(password, salt, algorithms, &Argon2Params::default())?;
    let encoded = encoder::encode(data).into_bytes();
    let initial = if locked { _t::_x(&encoded) } else { encoded };

    // Initialize buffer based on mode
    let mut buffer = match buffer_mode {
        BufferMode::Disk => LayerBuffer::switch_to_disk(Zeroizing::new(initial))?,
        BufferMode::Ram | BufferMode::Auto => LayerBuffer::new_ram(initial),
    };

    for (i, algo) in algorithms.iter().enumerate() {
        // Check memory pressure in auto mode (only when in RAM)
        if buffer_mode == BufferMode::Auto && !buffer.is_disk() {
            if let Ok(size) = buffer.len() {
                if should_switch_to_disk(size) {
                    // Memory pressure detected - switch to disk or fail
                    buffer.try_switch_to_disk()?;
                }
            }
        }

        let key = &keys[i];
        let algo_copy = *algo;
        buffer.process(|data| crypto::encrypt(algo_copy, key, data))?;
        progress(i + 1, total);
    }

    Ok(buffer.finalize()?.to_vec())
}

#[must_use = "encrypted data must be used"]
pub fn encrypt(
    data: &[u8],
    password: &[u8],
    algorithms: &[Algorithm],
) -> Result<Vec<u8>, CascadeError> {
    encrypt_with_progress(data, password, algorithms, |_, _| {})
}

#[must_use = "encrypted data must be used"]
pub fn encrypt_with_progress<F>(
    data: &[u8],
    password: &[u8],
    algorithms: &[Algorithm],
    progress: F,
) -> Result<Vec<u8>, CascadeError>
where
    F: FnMut(usize, usize),
{
    encrypt_with_buffer_mode(data, password, algorithms, BufferMode::Auto, progress)
}

#[must_use = "encrypted data must be used"]
pub fn encrypt_with_buffer_mode<F>(
    data: &[u8],
    password: &[u8],
    algorithms: &[Algorithm],
    buffer_mode: BufferMode,
    progress: F,
) -> Result<Vec<u8>, CascadeError>
where
    F: FnMut(usize, usize),
{
    if algorithms.is_empty() {
        return Err(CascadeError::NoAlgorithms);
    }
    let salt: [u8; 32] = rand::rng().random();
    let encrypted = encrypt_layers(
        data,
        password,
        algorithms,
        &salt,
        false,
        buffer_mode,
        progress,
    )?;
    let mut result = Header::with_ciphertext(algorithms.to_vec(), salt, false, &encrypted)
        .serialize()
        .into_bytes();
    result.extend(encrypted);
    Ok(result)
}

#[must_use = "encrypted data must be used"]
pub fn encrypt_protected(
    data: &[u8],
    password: &[u8],
    algorithms: &[Algorithm],
    recipient_public: &HybridPublicKey,
    locked: bool,
) -> Result<Vec<u8>, CascadeError> {
    encrypt_protected_with_progress(
        data,
        password,
        algorithms,
        recipient_public,
        locked,
        |_, _| {},
    )
}

#[must_use = "encrypted data must be used"]
pub fn encrypt_protected_with_progress<F>(
    data: &[u8],
    password: &[u8],
    algorithms: &[Algorithm],
    recipient_public: &HybridPublicKey,
    locked: bool,
    progress: F,
) -> Result<Vec<u8>, CascadeError>
where
    F: FnMut(usize, usize),
{
    encrypt_protected_with_buffer_mode(
        data,
        password,
        algorithms,
        recipient_public,
        locked,
        BufferMode::Auto,
        progress,
    )
}

#[must_use = "encrypted data must be used"]
pub fn encrypt_protected_with_buffer_mode<F>(
    data: &[u8],
    password: &[u8],
    algorithms: &[Algorithm],
    recipient_public: &HybridPublicKey,
    locked: bool,
    buffer_mode: BufferMode,
    progress: F,
) -> Result<Vec<u8>, CascadeError>
where
    F: FnMut(usize, usize),
{
    if algorithms.is_empty() {
        return Err(CascadeError::NoAlgorithms);
    }
    let salt: [u8; 32] = rand::rng().random();
    let encrypted = encrypt_layers(
        data,
        password,
        algorithms,
        &salt,
        locked,
        buffer_mode,
        progress,
    )?;
    let mut result = Header::with_ciphertext(algorithms.to_vec(), salt, locked, &encrypted)
        .serialize_encrypted(recipient_public)?
        .into_bytes();
    result.extend(encrypted);
    Ok(result)
}

#[must_use = "decrypted data must be used"]
pub fn decrypt(data: &[u8], password: &[u8]) -> Result<Zeroizing<Vec<u8>>, CascadeError> {
    decrypt_with_progress(data, password, |_, _| {})
}

#[must_use = "decrypted data must be used"]
pub fn decrypt_with_progress<F>(
    data: &[u8],
    password: &[u8],
    progress: F,
) -> Result<Zeroizing<Vec<u8>>, CascadeError>
where
    F: FnMut(usize, usize),
{
    decrypt_with_buffer_mode(data, password, BufferMode::Auto, progress)
}

#[must_use = "decrypted data must be used"]
pub fn decrypt_with_buffer_mode<F>(
    data: &[u8],
    password: &[u8],
    buffer_mode: BufferMode,
    progress: F,
) -> Result<Zeroizing<Vec<u8>>, CascadeError>
where
    F: FnMut(usize, usize),
{
    if Header::is_encrypted(data) {
        return Err(CascadeError::PrivateKeyRequired);
    }
    let (header, encrypted_data) = Header::parse(data)?;
    header.verify_ciphertext(encrypted_data)?;
    decrypt_layers(&header, encrypted_data, password, buffer_mode, progress)
}

#[must_use = "decrypted data must be used"]
pub fn decrypt_protected(
    data: &[u8],
    password: &[u8],
    private_key: &HybridPrivateKey,
) -> Result<Zeroizing<Vec<u8>>, CascadeError> {
    decrypt_protected_with_progress(data, password, private_key, |_, _| {})
}

#[must_use = "decrypted data must be used"]
pub fn decrypt_protected_with_progress<F>(
    data: &[u8],
    password: &[u8],
    private_key: &HybridPrivateKey,
    progress: F,
) -> Result<Zeroizing<Vec<u8>>, CascadeError>
where
    F: FnMut(usize, usize),
{
    decrypt_protected_with_buffer_mode(data, password, private_key, BufferMode::Auto, progress)
}

#[must_use = "decrypted data must be used"]
pub fn decrypt_protected_with_buffer_mode<F>(
    data: &[u8],
    password: &[u8],
    private_key: &HybridPrivateKey,
    buffer_mode: BufferMode,
    progress: F,
) -> Result<Zeroizing<Vec<u8>>, CascadeError>
where
    F: FnMut(usize, usize),
{
    let (header, encrypted_data) = if Header::is_encrypted(data) {
        Header::parse_encrypted(data, private_key)?
    } else {
        Header::parse(data)?
    };
    header.verify_ciphertext(encrypted_data)?;
    decrypt_layers(&header, encrypted_data, password, buffer_mode, progress)
}

pub(crate) fn decrypt_layers<F>(
    header: &Header,
    encrypted_data: &[u8],
    password: &[u8],
    buffer_mode: BufferMode,
    mut progress: F,
) -> Result<Zeroizing<Vec<u8>>, CascadeError>
where
    F: FnMut(usize, usize),
{
    if header.algorithms.is_empty() {
        return Err(CascadeError::NoAlgorithms);
    }
    let total = header.algorithms.len();
    let keys = derive_keys_parallel(
        password,
        &header.salt,
        &header.algorithms,
        &header.argon2_params,
    )?;

    // Initialize buffer based on mode
    let mut buffer = match buffer_mode {
        BufferMode::Disk => LayerBuffer::switch_to_disk(Zeroizing::new(encrypted_data.to_vec()))?,
        BufferMode::Ram | BufferMode::Auto => LayerBuffer::new_ram(encrypted_data.to_vec()),
    };

    for (i, algo) in header.algorithms.iter().rev().enumerate() {
        // Check memory pressure in auto mode (only when in RAM)
        if buffer_mode == BufferMode::Auto && !buffer.is_disk() {
            if let Ok(size) = buffer.len() {
                if should_switch_to_disk(size) {
                    // Memory pressure detected - switch to disk or fail
                    buffer.try_switch_to_disk()?;
                }
            }
        }

        // Map reverse iteration index back to original layer index
        let key_index = total - 1 - i;
        let key = &keys[key_index];
        let algo_copy = *algo;
        buffer.process(|data| crypto::decrypt(algo_copy, key, data))?;
        progress(i + 1, total);
    }

    let decrypted = buffer.finalize()?;
    let decrypted = if header.locked {
        Zeroizing::new(_t::_x(&decrypted))
    } else {
        decrypted
    };

    // Convert to string, discarding error details to avoid leaking sensitive bytes.
    // Wrong password produces garbage that fails UTF-8/base64 validation.
    let decoded_str = String::from_utf8(decrypted.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| {
            CascadeError::Crypto(CryptoError::DecryptionFailed(
                "Decryption failed - wrong password or corrupted data".into(),
            ))
        })?;
    encoder::decode(&decoded_str).map_err(|_| {
        CascadeError::Crypto(CryptoError::DecryptionFailed(
            "Decryption failed - wrong password or corrupted data".into(),
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid::HybridKeypair;
    use rand::Rng;

    fn random_password() -> Vec<u8> {
        let bytes: [u8; 16] = rand::rng().random();
        bytes.to_vec()
    }

    #[test]
    fn test_single_algorithm() {
        let data = b"Hello, cascrypt!";
        let password = random_password();
        let encrypted = encrypt(data, &password, &[Algorithm::Aes256]).unwrap();
        let decrypted = decrypt(&encrypted, &password).unwrap();
        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_full_cascade() {
        let data = b"Testing all four algorithms!";
        let password = random_password();
        let encrypted = encrypt(
            data,
            &password,
            &[
                Algorithm::Aes256,
                Algorithm::TripleDes,
                Algorithm::Twofish,
                Algorithm::Serpent,
            ],
        )
        .unwrap();
        let decrypted = decrypt(&encrypted, &password).unwrap();
        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_binary_data() {
        let data: Vec<u8> = (0..=255).collect();
        let password = random_password();
        let encrypted =
            encrypt(&data, &password, &[Algorithm::Serpent, Algorithm::Aes256]).unwrap();
        let decrypted = decrypt(&encrypted, &password).unwrap();
        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_password() {
        let data = b"Secret data";
        let correct_password = random_password();
        let wrong_password = random_password();
        let encrypted = encrypt(data, &correct_password, &[Algorithm::Aes256]).unwrap();
        assert!(decrypt(&encrypted, &wrong_password).is_err());
    }

    #[test]
    fn test_protected_encrypt_decrypt() {
        let data = b"Secret data with protected header";
        let password = random_password();
        let keypair = HybridKeypair::generate();

        let encrypted = encrypt_protected(
            data,
            &password,
            &[Algorithm::Aes256, Algorithm::ChaCha20Poly1305],
            &keypair.public,
            false,
        )
        .unwrap();

        assert!(Header::is_encrypted(&encrypted));
        let decrypted = decrypt_protected(&encrypted, &password, &keypair.private).unwrap();
        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_protected_requires_private_key() {
        let data = b"Secret data";
        let password = random_password();
        let keypair = HybridKeypair::generate();
        let encrypted = encrypt_protected(
            data,
            &password,
            &[Algorithm::Aes256],
            &keypair.public,
            false,
        )
        .unwrap();
        assert!(matches!(
            decrypt(&encrypted, &password),
            Err(CascadeError::PrivateKeyRequired)
        ));
    }

    #[test]
    fn test_locked_encrypt_decrypt() {
        let data = b"Locked secret data";
        let password = random_password();
        let keypair = HybridKeypair::generate();

        let encrypted = encrypt_protected(
            data,
            &password,
            &[Algorithm::Aes256],
            &keypair.public,
            true,
        )
        .unwrap();
        assert!(Header::is_encrypted(&encrypted));
        let decrypted = decrypt_protected(&encrypted, &password, &keypair.private).unwrap();
        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_seal_involution() {
        let a: &[u8] = &[0x48, 0x65, 0x6c, 0x6c, 0x6f];
        let b: &[u8] = &[0x55, 0x72, 0x79, 0x79, 0x62];
        assert_eq!(_t::_x(a), b);
        assert_eq!(_t::_x(b), a);
        assert_eq!(_t::_x(&_t::_x(a)), a);
    }

    #[test]
    fn test_ciphertext_tampering_detected() {
        let data = b"Secret data";
        let password = random_password();
        let mut encrypted = encrypt(data, &password, &[Algorithm::Aes256]).unwrap();
        // Tamper with ciphertext (last byte)
        let len = encrypted.len();
        encrypted[len - 1] ^= 0xFF;
        // Decryption should fail with ciphertext hash mismatch
        let result = decrypt(&encrypted, &password);
        assert!(result.is_err());
    }

    #[test]
    fn test_protected_ciphertext_tampering_detected() {
        let data = b"Secret data";
        let password = random_password();
        let keypair = HybridKeypair::generate();
        let mut encrypted = encrypt_protected(
            data,
            &password,
            &[Algorithm::Aes256],
            &keypair.public,
            false,
        )
        .unwrap();
        // Tamper with ciphertext (last byte)
        let len = encrypted.len();
        encrypted[len - 1] ^= 0xFF;
        // Decryption should fail with ciphertext hash mismatch
        let result = decrypt_protected(&encrypted, &password, &keypair.private);
        assert!(result.is_err());
    }

    #[test]
    fn test_duplicate_algorithms_different_keys() {
        // Test that duplicate algorithms in cascade get different keys per layer
        let data = b"Testing duplicate algorithm layers";
        let password = random_password();
        // Use same algorithm 3 times - each layer should get a unique key
        let encrypted = encrypt(
            data,
            &password,
            &[Algorithm::Aes256, Algorithm::Aes256, Algorithm::Aes256],
        )
        .unwrap();
        let decrypted = decrypt(&encrypted, &password).unwrap();
        assert_eq!(data.as_slice(), decrypted.as_slice());
    }
}
