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
    Seed,              // 'E' (Korean standard)
    Threefish256,      // '3' (Schneier's cipher)
    Rc6,               // '6' (AES finalist)
    Magma,             // 'G' (Russian GOST 28147-89)
    Speck128_256,      // 'P' (NSA lightweight)
    Gift128,           // 'J' (Lightweight cipher)
    Ascon128,          // 'N' (NIST 2023 winner)
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
        (Algorithm::Seed, 'E', "SEED-CBC", 16, b"cascade-seed"),
        (Algorithm::Threefish256, '3', "Threefish-256-CBC", 32, b"cascade-threefish"),
        (Algorithm::Rc6, '6', "RC6-CBC", 16, b"cascade-rc6"),
        (Algorithm::Magma, 'G', "Magma-CBC", 32, b"cascade-magma"),
        (Algorithm::Speck128_256, 'P', "Speck128/256-CBC", 32, b"cascade-speck"),
        (Algorithm::Gift128, 'J', "GIFT-128-CBC", 16, b"cascade-gift"),
        (Algorithm::Ascon128, 'N', "Ascon-128", 16, b"cascade-ascon"),
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

// Macro for cipher 0.5 block ciphers with manual CBC mode
macro_rules! cipher05_cbc_impl {
    ($cipher:ty, $key_len:expr, $block_size:expr) => {{
        use magma::cipher::{KeyInit, BlockCipherEncrypt, BlockCipherDecrypt};

        fn enc(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            if key.len() != $key_len { return Err(CryptoError::InvalidKeyLength { expected: $key_len, got: key.len() }); }
            let cipher = <$cipher>::new_from_slice(key).map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
            let mut iv = [0u8; $block_size];
            rand::thread_rng().fill_bytes(&mut iv);
            let padding_len = $block_size - (plaintext.len() % $block_size);
            let mut buffer = vec![padding_len as u8; plaintext.len() + padding_len];
            buffer[..plaintext.len()].copy_from_slice(plaintext);
            let mut prev = iv;
            for chunk in buffer.chunks_mut($block_size) {
                for (i, b) in chunk.iter_mut().enumerate() { *b ^= prev[i]; }
                let mut block = (*<&[u8; $block_size]>::try_from(&chunk[..]).unwrap()).into();
                cipher.encrypt_block(&mut block);
                chunk.copy_from_slice(&block);
                prev.copy_from_slice(chunk);
            }
            let mut result = Vec::with_capacity($block_size + buffer.len());
            result.extend_from_slice(&iv);
            result.extend(buffer);
            Ok(result)
        }

        fn dec(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            if key.len() != $key_len { return Err(CryptoError::InvalidKeyLength { expected: $key_len, got: key.len() }); }
            if ciphertext.len() < $block_size { return Err(CryptoError::InvalidNonce); }
            let cipher = <$cipher>::new_from_slice(key).map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
            let (iv, data) = ciphertext.split_at($block_size);
            let mut buffer = data.to_vec();
            let mut prev = [0u8; $block_size];
            prev.copy_from_slice(iv);
            for chunk in buffer.chunks_mut($block_size) {
                let mut ct_backup = [0u8; $block_size];
                ct_backup.copy_from_slice(chunk);
                let mut block = (*<&[u8; $block_size]>::try_from(&chunk[..]).unwrap()).into();
                cipher.decrypt_block(&mut block);
                chunk.copy_from_slice(&block);
                for (i, b) in chunk.iter_mut().enumerate() { *b ^= prev[i]; }
                prev = ct_backup;
            }
            let padding_len = *buffer.last().ok_or_else(|| CryptoError::DecryptionFailed("Empty".into()))? as usize;
            if padding_len == 0 || padding_len > $block_size || padding_len > buffer.len() || !buffer[buffer.len() - padding_len..].iter().all(|&b| b == padding_len as u8) {
                return Err(CryptoError::DecryptionFailed("Invalid padding".into()));
            }
            buffer.truncate(buffer.len() - padding_len);
            Ok(buffer)
        }

        (enc as fn(&[u8], &[u8]) -> Result<Vec<u8>, CryptoError>,
         dec as fn(&[u8], &[u8]) -> Result<Vec<u8>, CryptoError>)
    }};
}

fn ascon_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use ascon_aead::{AsconAead128, aead::{Aead, KeyInit}};
    const KEY_LEN: usize = 16;
    const NONCE_SIZE: usize = 16;
    if key.len() != KEY_LEN { return Err(CryptoError::InvalidKeyLength { expected: KEY_LEN, got: key.len() }); }
    let key_arr: [u8; KEY_LEN] = key.try_into().unwrap();
    let cipher = AsconAead128::new(&key_arr.into());
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher.encrypt(&nonce.into(), plaintext).map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    let mut result = Vec::with_capacity(NONCE_SIZE + ct.len());
    result.extend_from_slice(&nonce);
    result.extend(ct);
    Ok(result)
}

fn ascon_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use ascon_aead::{AsconAead128, aead::{Aead, KeyInit}};
    const KEY_LEN: usize = 16;
    const NONCE_SIZE: usize = 16;
    if key.len() != KEY_LEN { return Err(CryptoError::InvalidKeyLength { expected: KEY_LEN, got: key.len() }); }
    if ciphertext.len() < NONCE_SIZE { return Err(CryptoError::InvalidNonce); }
    let key_arr: [u8; KEY_LEN] = key.try_into().unwrap();
    let cipher = AsconAead128::new(&key_arr.into());
    let (nonce, data) = ciphertext.split_at(NONCE_SIZE);
    let nonce_arr: [u8; NONCE_SIZE] = nonce.try_into().unwrap();
    cipher.decrypt(&nonce_arr.into(), data).map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

// Custom implementation for Threefish256 (uses cipher 0.2 API)
macro_rules! threefish_impl {
    () => {{
        use threefish_cipher::{Threefish256, NewBlockCipher, BlockCipher};
        use cipher::generic_array::GenericArray;
        const BLOCK_SIZE: usize = 32;

        fn enc(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            if key.len() != BLOCK_SIZE { return Err(CryptoError::InvalidKeyLength { expected: BLOCK_SIZE, got: key.len() }); }
            let cipher = Threefish256::new(GenericArray::from_slice(key));
            let mut iv = [0u8; BLOCK_SIZE];
            rand::thread_rng().fill_bytes(&mut iv);
            let padding_len = BLOCK_SIZE - (plaintext.len() % BLOCK_SIZE);
            let mut buffer = vec![padding_len as u8; plaintext.len() + padding_len];
            buffer[..plaintext.len()].copy_from_slice(plaintext);
            let mut prev = iv;
            for chunk in buffer.chunks_mut(BLOCK_SIZE) {
                for (i, b) in chunk.iter_mut().enumerate() { *b ^= prev[i]; }
                let mut block = GenericArray::clone_from_slice(chunk);
                cipher.encrypt_block(&mut block);
                chunk.copy_from_slice(&block);
                prev.copy_from_slice(chunk);
            }
            let mut result = Vec::with_capacity(BLOCK_SIZE + buffer.len());
            result.extend_from_slice(&iv);
            result.extend(buffer);
            Ok(result)
        }

        fn dec(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            if key.len() != BLOCK_SIZE { return Err(CryptoError::InvalidKeyLength { expected: BLOCK_SIZE, got: key.len() }); }
            if ciphertext.len() < BLOCK_SIZE { return Err(CryptoError::InvalidNonce); }
            let cipher = Threefish256::new(GenericArray::from_slice(key));
            let (iv, data) = ciphertext.split_at(BLOCK_SIZE);
            let mut buffer = data.to_vec();
            let mut prev = [0u8; BLOCK_SIZE];
            prev.copy_from_slice(iv);
            for chunk in buffer.chunks_mut(BLOCK_SIZE) {
                let mut ct_backup = [0u8; BLOCK_SIZE];
                ct_backup.copy_from_slice(chunk);
                let mut block = GenericArray::clone_from_slice(chunk);
                cipher.decrypt_block(&mut block);
                chunk.copy_from_slice(&block);
                for (i, b) in chunk.iter_mut().enumerate() { *b ^= prev[i]; }
                prev = ct_backup;
            }
            let padding_len = *buffer.last().ok_or_else(|| CryptoError::DecryptionFailed("Empty".into()))? as usize;
            if padding_len == 0 || padding_len > BLOCK_SIZE || padding_len > buffer.len() || !buffer[buffer.len() - padding_len..].iter().all(|&b| b == padding_len as u8) {
                return Err(CryptoError::DecryptionFailed("Invalid padding".into()));
            }
            buffer.truncate(buffer.len() - padding_len);
            Ok(buffer)
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
        Algorithm::Seed => cbc_impl!(kisaseed::SEED, 16, 16, 16),
        Algorithm::Threefish256 => threefish_impl!(),
        Algorithm::Rc6 => cipher05_cbc_impl!(rc6::RC6_32_20_16, 16, 16),
        Algorithm::Magma => cipher05_cbc_impl!(magma::Magma, 32, 8),
        Algorithm::Speck128_256 => cipher05_cbc_impl!(speck_cipher::Speck128_256, 32, 16),
        Algorithm::Gift128 => cipher05_cbc_impl!(gift_cipher::Gift128, 16, 16),
        Algorithm::Ascon128 => (ascon_encrypt, ascon_decrypt),
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
    #[test] fn test_seed() { test_roundtrip(Algorithm::Seed); }
    #[test] fn test_threefish256() { test_roundtrip(Algorithm::Threefish256); }
    #[test] fn test_rc6() { test_roundtrip(Algorithm::Rc6); }
    #[test] fn test_magma() { test_roundtrip(Algorithm::Magma); }
    #[test] fn test_speck128_256() { test_roundtrip(Algorithm::Speck128_256); }
    #[test] fn test_gift128() { test_roundtrip(Algorithm::Gift128); }
    #[test] fn test_ascon128() { test_roundtrip(Algorithm::Ascon128); }

    #[test]
    fn test_different_nonces() {
        let key = [0x42u8; 32];
        let plaintext = b"Same plaintext";
        let e1 = encrypt(Algorithm::Aes256, &key, plaintext).unwrap();
        let e2 = encrypt(Algorithm::Aes256, &key, plaintext).unwrap();
        assert_ne!(e1, e2);
    }
}
