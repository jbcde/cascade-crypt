use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;

use super::{Algorithm, Cipher, CryptoError};

const NONCE_SIZE: usize = 24; // Extended nonce for XChaCha

pub struct XChaCha20Poly1305Cipher;

impl Cipher for XChaCha20Poly1305Cipher {
    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                got: key.len(),
            });
        }

        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

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

        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        let nonce = XNonce::from_slice(&ciphertext[..NONCE_SIZE]);
        let encrypted_data = &ciphertext[NONCE_SIZE..];

        cipher
            .decrypt(nonce, encrypted_data)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::XChaCha20Poly1305
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xchacha20_roundtrip() {
        let cipher = XChaCha20Poly1305Cipher;
        let key = [0x42u8; 32];
        let plaintext = b"Hello, XChaCha20-Poly1305!";

        let encrypted = cipher.encrypt(&key, plaintext).unwrap();
        let decrypted = cipher.decrypt(&key, &encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
