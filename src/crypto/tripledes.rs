use cbc::{Decryptor, Encryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use des::TdesEde3;
use rand::RngCore;

use super::{Algorithm, Cipher, CryptoError};

type TdesEnc = Encryptor<TdesEde3>;
type TdesDec = Decryptor<TdesEde3>;

const IV_SIZE: usize = 8; // 64-bit IV for 3DES
const BLOCK_SIZE: usize = 8; // 64-bit block for 3DES

pub struct TripleDesCipher;

impl Cipher for TripleDesCipher {
    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if key.len() != 24 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 24,
                got: key.len(),
            });
        }

        // Generate random IV
        let mut iv = [0u8; IV_SIZE];
        rand::thread_rng().fill_bytes(&mut iv);

        let cipher = TdesEnc::new_from_slices(key, &iv)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        // Calculate padded size (PKCS7 padding)
        let padding_len = BLOCK_SIZE - (plaintext.len() % BLOCK_SIZE);
        let padded_len = plaintext.len() + padding_len;

        // Create buffer with plaintext and padding
        let mut buffer = vec![0u8; padded_len];
        buffer[..plaintext.len()].copy_from_slice(plaintext);
        // PKCS7 padding: fill remaining bytes with the padding length
        for b in buffer[plaintext.len()..].iter_mut() {
            *b = padding_len as u8;
        }

        cipher
            .encrypt_padded_mut::<block_padding::NoPadding>(&mut buffer, padded_len)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        // Prepend IV to ciphertext
        let mut result = Vec::with_capacity(IV_SIZE + buffer.len());
        result.extend_from_slice(&iv);
        result.extend(buffer);

        Ok(result)
    }

    fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if key.len() != 24 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 24,
                got: key.len(),
            });
        }

        if ciphertext.len() < IV_SIZE {
            return Err(CryptoError::InvalidNonce);
        }

        let iv = &ciphertext[..IV_SIZE];
        let encrypted_data = &ciphertext[IV_SIZE..];

        let cipher = TdesDec::new_from_slices(key, iv)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        let mut buffer = encrypted_data.to_vec();

        cipher
            .decrypt_padded_mut::<block_padding::NoPadding>(&mut buffer)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        // Remove PKCS7 padding
        if buffer.is_empty() {
            return Err(CryptoError::DecryptionFailed("Empty decrypted data".into()));
        }
        let padding_len = *buffer.last().unwrap() as usize;
        if padding_len == 0 || padding_len > BLOCK_SIZE || padding_len > buffer.len() {
            return Err(CryptoError::DecryptionFailed("Invalid padding".into()));
        }
        // Verify padding bytes
        for &b in &buffer[buffer.len() - padding_len..] {
            if b != padding_len as u8 {
                return Err(CryptoError::DecryptionFailed("Invalid padding".into()));
            }
        }
        buffer.truncate(buffer.len() - padding_len);

        Ok(buffer)
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::TripleDes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_3des_roundtrip() {
        let cipher = TripleDesCipher;
        let key = [0x42u8; 24];
        let plaintext = b"Hello, 3DES!";

        let encrypted = cipher.encrypt(&key, plaintext).unwrap();
        let decrypted = cipher.decrypt(&key, &encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
