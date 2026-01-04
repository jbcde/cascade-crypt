use rand::RngCore;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
    #[error("Invalid nonce/IV")]
    InvalidNonce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    Aes256,            // 'A'
    TripleDes,         // 'T'
    Twofish,           // 'W'
    Serpent,           // 'S'
    ChaCha20Poly1305,  // 'C'
    XChaCha20Poly1305, // 'X'
    Camellia,          // 'M'
    Blowfish,          // 'B'
    Cast5,             // 'F'
    Idea,              // 'I'
    Aria,              // 'R'
    Sm4,               // '4'
    Kuznyechik,        // 'K'
}

impl Algorithm {
    const DATA: &'static [(Algorithm, char, &'static str, usize, &'static [u8])] = &[
        (Algorithm::Aes256, 'A', "AES-256-GCM", 32, b"cascade-aes256"),
        (Algorithm::TripleDes, 'T', "3DES-CBC", 24, b"cascade-3des"),
        (Algorithm::Twofish, 'W', "Twofish-256-CBC", 32, b"cascade-twofish"),
        (Algorithm::Serpent, 'S', "Serpent-256-CBC", 32, b"cascade-serpent"),
        (Algorithm::ChaCha20Poly1305, 'C', "ChaCha20-Poly1305", 32, b"cascade-chacha20"),
        (Algorithm::XChaCha20Poly1305, 'X', "XChaCha20-Poly1305", 32, b"cascade-xchacha20"),
        (Algorithm::Camellia, 'M', "Camellia-256-CBC", 32, b"cascade-camellia"),
        (Algorithm::Blowfish, 'B', "Blowfish-256-CBC", 32, b"cascade-blowfish"),
        (Algorithm::Cast5, 'F', "CAST5-CBC", 16, b"cascade-cast5"),
        (Algorithm::Idea, 'I', "IDEA-CBC", 16, b"cascade-idea"),
        (Algorithm::Aria, 'R', "ARIA-256-CBC", 32, b"cascade-aria"),
        (Algorithm::Sm4, '4', "SM4-CBC", 16, b"cascade-sm4"),
        (Algorithm::Kuznyechik, 'K', "Kuznyechik-CBC", 32, b"cascade-kuznyechik"),
    ];

    fn data(&self) -> (char, &'static str, usize, &'static [u8]) {
        let (_, c, n, k, s) = Self::DATA.iter().find(|(a, _, _, _, _)| a == self).unwrap();
        (*c, *n, *k, *s)
    }

    pub fn code(&self) -> char { self.data().0 }
    pub fn name(&self) -> &'static str { self.data().1 }
    pub fn key_size(&self) -> usize { self.data().2 }
    pub fn salt_context(&self) -> &'static [u8] { self.data().3 }

    pub fn from_code(c: char) -> Option<Algorithm> {
        Self::DATA.iter().find(|(_, code, _, _, _)| *code == c).map(|(a, _, _, _, _)| *a)
    }
}

// Macro for CBC ciphers
macro_rules! cbc_impl {
    ($cipher:ty, $key_len:expr, $iv_size:expr, $block_size:expr) => {{
        use cbc::{Decryptor, Encryptor};
        use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

        fn enc(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            if key.len() != $key_len {
                return Err(CryptoError::InvalidKeyLength { expected: $key_len, got: key.len() });
            }
            let mut iv = [0u8; $iv_size];
            rand::thread_rng().fill_bytes(&mut iv);
            let cipher = Encryptor::<$cipher>::new_from_slices(key, &iv)
                .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

            let padding_len = $block_size - (plaintext.len() % $block_size);
            let mut buffer = vec![padding_len as u8; plaintext.len() + padding_len];
            buffer[..plaintext.len()].copy_from_slice(plaintext);
            let len = buffer.len();

            cipher.encrypt_padded_mut::<block_padding::NoPadding>(&mut buffer, len)
                .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

            let mut result = Vec::with_capacity($iv_size + buffer.len());
            result.extend_from_slice(&iv);
            result.extend(buffer);
            Ok(result)
        }

        fn dec(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            if key.len() != $key_len {
                return Err(CryptoError::InvalidKeyLength { expected: $key_len, got: key.len() });
            }
            if ciphertext.len() < $iv_size {
                return Err(CryptoError::InvalidNonce);
            }
            let (iv, data) = ciphertext.split_at($iv_size);
            let cipher = Decryptor::<$cipher>::new_from_slices(key, iv)
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

            let mut buffer = data.to_vec();
            cipher.decrypt_padded_mut::<block_padding::NoPadding>(&mut buffer)
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

            let padding_len = *buffer.last().ok_or_else(|| CryptoError::DecryptionFailed("Empty".into()))? as usize;
            if padding_len == 0 || padding_len > $block_size || padding_len > buffer.len()
                || !buffer[buffer.len() - padding_len..].iter().all(|&b| b == padding_len as u8) {
                return Err(CryptoError::DecryptionFailed("Invalid padding".into()));
            }
            buffer.truncate(buffer.len() - padding_len);
            Ok(buffer)
        }

        (enc as fn(&[u8], &[u8]) -> Result<Vec<u8>, CryptoError>,
         dec as fn(&[u8], &[u8]) -> Result<Vec<u8>, CryptoError>)
    }};
}

// Macro for AEAD ciphers
macro_rules! aead_impl {
    ($cipher:ty, $nonce_size:expr) => {{
        use aes_gcm::aead::{Aead, KeyInit, generic_array::GenericArray};

        fn enc(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            if key.len() != 32 {
                return Err(CryptoError::InvalidKeyLength { expected: 32, got: key.len() });
            }
            let cipher = <$cipher>::new_from_slice(key)
                .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
            let mut nonce = [0u8; $nonce_size];
            rand::thread_rng().fill_bytes(&mut nonce);
            let ct = cipher.encrypt(GenericArray::from_slice(&nonce), plaintext)
                .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
            let mut result = Vec::with_capacity($nonce_size + ct.len());
            result.extend_from_slice(&nonce);
            result.extend(ct);
            Ok(result)
        }

        fn dec(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            if key.len() != 32 {
                return Err(CryptoError::InvalidKeyLength { expected: 32, got: key.len() });
            }
            if ciphertext.len() < $nonce_size {
                return Err(CryptoError::InvalidNonce);
            }
            let cipher = <$cipher>::new_from_slice(key)
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
            let (nonce, data) = ciphertext.split_at($nonce_size);
            cipher.decrypt(GenericArray::from_slice(nonce), data)
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
        }

        (enc as fn(&[u8], &[u8]) -> Result<Vec<u8>, CryptoError>,
         dec as fn(&[u8], &[u8]) -> Result<Vec<u8>, CryptoError>)
    }};
}

pub fn encrypt(algo: Algorithm, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let (enc, _) = get_cipher_fns(algo);
    enc(key, plaintext)
}

pub fn decrypt(algo: Algorithm, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let (_, dec) = get_cipher_fns(algo);
    dec(key, ciphertext)
}

fn get_cipher_fns(algo: Algorithm) -> (fn(&[u8], &[u8]) -> Result<Vec<u8>, CryptoError>, fn(&[u8], &[u8]) -> Result<Vec<u8>, CryptoError>) {
    match algo {
        Algorithm::Aes256 => aead_impl!(aes_gcm::Aes256Gcm, 12),
        Algorithm::ChaCha20Poly1305 => aead_impl!(chacha20poly1305::ChaCha20Poly1305, 12),
        Algorithm::XChaCha20Poly1305 => aead_impl!(chacha20poly1305::XChaCha20Poly1305, 24),
        Algorithm::TripleDes => cbc_impl!(des::TdesEde3, 24, 8, 8),
        Algorithm::Twofish => cbc_impl!(twofish::Twofish, 32, 16, 16),
        Algorithm::Serpent => cbc_impl!(serpent::Serpent, 32, 16, 16),
        Algorithm::Camellia => cbc_impl!(camellia::Camellia256, 32, 16, 16),
        Algorithm::Blowfish => cbc_impl!(blowfish::Blowfish, 32, 8, 8),
        Algorithm::Cast5 => cbc_impl!(cast5::Cast5, 16, 8, 8),
        Algorithm::Idea => cbc_impl!(idea::Idea, 16, 8, 8),
        Algorithm::Aria => cbc_impl!(aria::Aria256, 32, 16, 16),
        Algorithm::Sm4 => cbc_impl!(sm4::Sm4, 16, 16, 16),
        Algorithm::Kuznyechik => cbc_impl!(kuznyechik::Kuznyechik, 32, 16, 16),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_roundtrip(algo: Algorithm) {
        let key = vec![0x42u8; algo.key_size()];
        let plaintext = b"Hello, cascade-crypt!";
        let encrypted = encrypt(algo, &key, plaintext).unwrap();
        let decrypted = decrypt(algo, &key, &encrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test] fn test_aes256() { test_roundtrip(Algorithm::Aes256); }
    #[test] fn test_tripledes() { test_roundtrip(Algorithm::TripleDes); }
    #[test] fn test_twofish() { test_roundtrip(Algorithm::Twofish); }
    #[test] fn test_serpent() { test_roundtrip(Algorithm::Serpent); }
    #[test] fn test_chacha20() { test_roundtrip(Algorithm::ChaCha20Poly1305); }
    #[test] fn test_xchacha20() { test_roundtrip(Algorithm::XChaCha20Poly1305); }
    #[test] fn test_camellia() { test_roundtrip(Algorithm::Camellia); }
    #[test] fn test_blowfish() { test_roundtrip(Algorithm::Blowfish); }
    #[test] fn test_cast5() { test_roundtrip(Algorithm::Cast5); }
    #[test] fn test_idea() { test_roundtrip(Algorithm::Idea); }
    #[test] fn test_aria() { test_roundtrip(Algorithm::Aria); }
    #[test] fn test_sm4() { test_roundtrip(Algorithm::Sm4); }
    #[test] fn test_kuznyechik() { test_roundtrip(Algorithm::Kuznyechik); }

    #[test]
    fn test_different_nonces() {
        let key = [0x42u8; 32];
        let plaintext = b"Same plaintext";
        let e1 = encrypt(Algorithm::Aes256, &key, plaintext).unwrap();
        let e2 = encrypt(Algorithm::Aes256, &key, plaintext).unwrap();
        assert_ne!(e1, e2);
    }
}
