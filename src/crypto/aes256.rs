use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;

use super::{Algorithm, Cipher, CryptoError};

const NONCE_SIZE: usize = 12;

pub struct Aes256Cipher;

impl Cipher for Aes256Cipher {
    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                got: key.len(),
            });
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend(ciphertext);

        Ok(result)
    }

    fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                got: key.len(),
            });
        }

        if ciphertext.len() < NONCE_SIZE {
            return Err(CryptoError::InvalidNonce);
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        let nonce = Nonce::from_slice(&ciphertext[..NONCE_SIZE]);
        let encrypted_data = &ciphertext[NONCE_SIZE..];

        cipher
            .decrypt(nonce, encrypted_data)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::Aes256
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_roundtrip() {
        let cipher = Aes256Cipher;
        let key = [0x42u8; 32];
        let plaintext = b"Hello, AES-256!";

        let encrypted = cipher.encrypt(&key, plaintext).unwrap();
        let decrypted = cipher.decrypt(&key, &encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_aes256_different_nonces() {
        let cipher = Aes256Cipher;
        let key = [0x42u8; 32];
        let plaintext = b"Same plaintext";

        let encrypted1 = cipher.encrypt(&key, plaintext).unwrap();
        let encrypted2 = cipher.encrypt(&key, plaintext).unwrap();

        // Different nonces should produce different ciphertexts
        assert_ne!(encrypted1, encrypted2);
    }
}
