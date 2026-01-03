use argon2::Argon2;
use rand::RngCore;
use thiserror::Error;

use crate::crypto::{create_cipher, Algorithm, CryptoError};
use crate::encoder;
use crate::header::{Header, HeaderError};

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
}

/// Derive a key for a specific algorithm from the master password
fn derive_key(password: &[u8], salt: &[u8], algo: Algorithm) -> Result<Vec<u8>, CascadeError> {
    let argon2 = Argon2::default();

    // Combine master salt with algorithm-specific context
    let mut full_salt = Vec::with_capacity(salt.len() + algo.salt_context().len());
    full_salt.extend_from_slice(salt);
    full_salt.extend_from_slice(algo.salt_context());

    let key_size = algo.key_size();
    let mut key = vec![0u8; key_size];

    argon2
        .hash_password_into(password, &full_salt, &mut key)
        .map_err(|_| CascadeError::KeyDerivation)?;

    Ok(key)
}

/// Encrypt data with cascading algorithms
pub fn encrypt(
    data: &[u8],
    password: &[u8],
    algorithms: Vec<Algorithm>,
) -> Result<Vec<u8>, CascadeError> {
    if algorithms.is_empty() {
        return Err(CascadeError::NoAlgorithms);
    }

    // Generate random master salt
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);

    // Encode binary to base64 first
    let encoded = encoder::encode(data);
    let mut current_data = encoded.into_bytes();

    // Apply each cipher in order
    for algo in &algorithms {
        let key = derive_key(password, &salt, *algo)?;
        let cipher = create_cipher(*algo);
        current_data = cipher.encrypt(&key, &current_data)?;
    }

    // Create header
    let header = Header::new(algorithms, salt);

    // Combine header and encrypted data
    let mut result = header.serialize().into_bytes();
    result.extend(current_data);

    Ok(result)
}

/// Decrypt data by reversing the cascade
pub fn decrypt(data: &[u8], password: &[u8]) -> Result<Vec<u8>, CascadeError> {
    // Parse header to get algorithm order and salt
    let (header, encrypted_data) = Header::parse(data)?;

    if header.algorithms.is_empty() {
        return Err(CascadeError::NoAlgorithms);
    }

    let mut current_data = encrypted_data.to_vec();

    // Apply decryption in reverse order
    for algo in header.algorithms.iter().rev() {
        let key = derive_key(password, &header.salt, *algo)?;
        let cipher = create_cipher(*algo);
        current_data = cipher.decrypt(&key, &current_data)?;
    }

    // Decode from base64 back to binary
    let decoded_str = String::from_utf8(current_data).map_err(|_| {
        CascadeError::Crypto(CryptoError::DecryptionFailed(
            "Invalid UTF-8 after decryption".into(),
        ))
    })?;

    let result = encoder::decode(&decoded_str)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let encrypted = encrypt(
            &data,
            password,
            vec![Algorithm::Serpent, Algorithm::Aes256],
        )
        .unwrap();

        let decrypted = decrypt(&encrypted, password).unwrap();
        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_wrong_password() {
        let data = b"Secret data";
        let password = b"correct-password";
        let wrong_password = b"wrong-password";

        let encrypted = encrypt(data, password, vec![Algorithm::Aes256]).unwrap();
        let result = decrypt(&encrypted, wrong_password);

        assert!(result.is_err());
    }
}
