use rand::RngCore;
use thiserror::Error;

/// Type alias for cipher encrypt/decrypt function pointers
pub type CipherFn = fn(&[u8], &[u8]) -> Result<Vec<u8>, CryptoError>;

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
    #[inline]
    #[must_use]
    pub const fn code(&self) -> char {
        match self {
            Self::Aes256 => 'A',
            Self::TripleDes => 'T',
            Self::Twofish => 'W',
            Self::Serpent => 'S',
            Self::ChaCha20Poly1305 => 'C',
            Self::XChaCha20Poly1305 => 'X',
            Self::Camellia => 'M',
            Self::Blowfish => 'B',
            Self::Cast5 => 'F',
            Self::Idea => 'I',
            Self::Aria => 'R',
            Self::Sm4 => '4',
            Self::Kuznyechik => 'K',
            Self::Seed => 'E',
            Self::Threefish256 => '3',
            Self::Rc6 => '6',
            Self::Magma => 'G',
            Self::Speck128_256 => 'P',
            Self::Gift128 => 'J',
            Self::Ascon128 => 'N',
        }
    }

    #[inline]
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Aes256 => "AES-256-GCM",
            Self::TripleDes => "3DES-CBC",
            Self::Twofish => "Twofish-256-CBC",
            Self::Serpent => "Serpent-256-CBC",
            Self::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            Self::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            Self::Camellia => "Camellia-256-CBC",
            Self::Blowfish => "Blowfish-256-CBC",
            Self::Cast5 => "CAST5-CBC",
            Self::Idea => "IDEA-CBC",
            Self::Aria => "ARIA-256-CBC",
            Self::Sm4 => "SM4-CBC",
            Self::Kuznyechik => "Kuznyechik-CBC",
            Self::Seed => "SEED-CBC",
            Self::Threefish256 => "Threefish-256-CBC",
            Self::Rc6 => "RC6-CBC",
            Self::Magma => "Magma-CBC",
            Self::Speck128_256 => "Speck128/256-CBC",
            Self::Gift128 => "GIFT-128-CBC",
            Self::Ascon128 => "Ascon-128",
        }
    }

    #[inline]
    #[must_use]
    pub const fn key_size(&self) -> usize {
        match self {
            Self::Aes256
            | Self::Twofish
            | Self::Serpent
            | Self::ChaCha20Poly1305
            | Self::XChaCha20Poly1305
            | Self::Camellia
            | Self::Blowfish
            | Self::Aria
            | Self::Kuznyechik
            | Self::Threefish256
            | Self::Magma
            | Self::Speck128_256 => 32,
            Self::TripleDes => 24,
            Self::Cast5
            | Self::Idea
            | Self::Sm4
            | Self::Seed
            | Self::Rc6
            | Self::Gift128
            | Self::Ascon128 => 16,
        }
    }

    #[inline]
    #[must_use]
    pub const fn salt_context(&self) -> &'static [u8] {
        match self {
            Self::Aes256 => b"cascade-aes256",
            Self::TripleDes => b"cascade-3des",
            Self::Twofish => b"cascade-twofish",
            Self::Serpent => b"cascade-serpent",
            Self::ChaCha20Poly1305 => b"cascade-chacha20",
            Self::XChaCha20Poly1305 => b"cascade-xchacha20",
            Self::Camellia => b"cascade-camellia",
            Self::Blowfish => b"cascade-blowfish",
            Self::Cast5 => b"cascade-cast5",
            Self::Idea => b"cascade-idea",
            Self::Aria => b"cascade-aria",
            Self::Sm4 => b"cascade-sm4",
            Self::Kuznyechik => b"cascade-kuznyechik",
            Self::Seed => b"cascade-seed",
            Self::Threefish256 => b"cascade-threefish",
            Self::Rc6 => b"cascade-rc6",
            Self::Magma => b"cascade-magma",
            Self::Speck128_256 => b"cascade-speck",
            Self::Gift128 => b"cascade-gift",
            Self::Ascon128 => b"cascade-ascon",
        }
    }

    #[inline]
    #[must_use]
    pub const fn from_code(c: char) -> Option<Algorithm> {
        match c {
            'A' => Some(Self::Aes256),
            'T' => Some(Self::TripleDes),
            'W' => Some(Self::Twofish),
            'S' => Some(Self::Serpent),
            'C' => Some(Self::ChaCha20Poly1305),
            'X' => Some(Self::XChaCha20Poly1305),
            'M' => Some(Self::Camellia),
            'B' => Some(Self::Blowfish),
            'F' => Some(Self::Cast5),
            'I' => Some(Self::Idea),
            'R' => Some(Self::Aria),
            '4' => Some(Self::Sm4),
            'K' => Some(Self::Kuznyechik),
            'E' => Some(Self::Seed),
            '3' => Some(Self::Threefish256),
            '6' => Some(Self::Rc6),
            'G' => Some(Self::Magma),
            'P' => Some(Self::Speck128_256),
            'J' => Some(Self::Gift128),
            'N' => Some(Self::Ascon128),
            _ => None,
        }
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// Macro for CBC ciphers
macro_rules! cbc_impl {
    ($cipher:ty, $key_len:expr, $iv_size:expr, $block_size:expr) => {{
        use cbc::{Decryptor, Encryptor};
        use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

        fn enc(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            if key.len() != $key_len {
                return Err(CryptoError::InvalidKeyLength {
                    expected: $key_len,
                    got: key.len(),
                });
            }
            let mut iv = [0u8; $iv_size];
            rand::rng().fill_bytes(&mut iv);
            let cipher = Encryptor::<$cipher>::new_from_slices(key, &iv)
                .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

            let padding_len = $block_size - (plaintext.len() % $block_size);
            let mut buffer = vec![padding_len as u8; plaintext.len() + padding_len];
            buffer[..plaintext.len()].copy_from_slice(plaintext);
            let len = buffer.len();

            cipher
                .encrypt_padded_mut::<block_padding::NoPadding>(&mut buffer, len)
                .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

            let mut result = Vec::with_capacity($iv_size + buffer.len());
            result.extend_from_slice(&iv);
            result.extend(buffer);
            Ok(result)
        }

        fn dec(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            if key.len() != $key_len {
                return Err(CryptoError::InvalidKeyLength {
                    expected: $key_len,
                    got: key.len(),
                });
            }
            if ciphertext.len() < $iv_size {
                return Err(CryptoError::InvalidNonce);
            }
            let (iv, data) = ciphertext.split_at($iv_size);
            let cipher = Decryptor::<$cipher>::new_from_slices(key, iv)
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

            let mut buffer = data.to_vec();
            cipher
                .decrypt_padded_mut::<block_padding::NoPadding>(&mut buffer)
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

            let last_byte = *buffer
                .last()
                .ok_or_else(|| CryptoError::DecryptionFailed("Empty".into()))?;
            let padding_len = last_byte as usize;

            // Fully constant-time padding validation.
            // Always examines exactly $block_size bytes to prevent leaking
            // the padding value via timing.
            let block_size: usize = $block_size;
            let valid = ((padding_len >= 1) as u8) & ((padding_len <= block_size) as u8);
            let mut bad = valid ^ 1; // 1 if length is already invalid

            let check_start = buffer.len() - block_size;
            let threshold = block_size.saturating_sub(padding_len);
            for i in 0..block_size {
                let in_pad = ((i >= threshold) as u8) & valid;
                bad |= in_pad & (buffer[check_start + i] ^ last_byte);
            }

            if bad != 0 {
                return Err(CryptoError::DecryptionFailed("Invalid padding".into()));
            }
            buffer.truncate(buffer.len() - padding_len);
            Ok(buffer)
        }

        (enc as CipherFn, dec as CipherFn)
    }};
}

// Macro for AEAD ciphers
macro_rules! aead_impl {
    ($cipher:ty, $nonce_size:expr) => {{
        use aes_gcm::aead::{generic_array::GenericArray, Aead, KeyInit};

        fn enc(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            if key.len() != 32 {
                return Err(CryptoError::InvalidKeyLength {
                    expected: 32,
                    got: key.len(),
                });
            }
            let cipher = <$cipher>::new_from_slice(key)
                .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
            let mut nonce = [0u8; $nonce_size];
            rand::rng().fill_bytes(&mut nonce);
            let ct = cipher
                .encrypt(GenericArray::from_slice(&nonce), plaintext)
                .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
            let mut result = Vec::with_capacity($nonce_size + ct.len());
            result.extend_from_slice(&nonce);
            result.extend(ct);
            Ok(result)
        }

        fn dec(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            if key.len() != 32 {
                return Err(CryptoError::InvalidKeyLength {
                    expected: 32,
                    got: key.len(),
                });
            }
            if ciphertext.len() < $nonce_size {
                return Err(CryptoError::InvalidNonce);
            }
            let cipher = <$cipher>::new_from_slice(key)
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
            let (nonce, data) = ciphertext.split_at($nonce_size);
            cipher
                .decrypt(GenericArray::from_slice(nonce), data)
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
        }

        (enc as CipherFn, dec as CipherFn)
    }};
}

// Macro for cipher 0.5 block ciphers with manual CBC mode.
//
// These ciphers (Threefish, RC6, Magma, Speck, GIFT) use the cipher 0.5 trait
// ecosystem, but our Cargo.toml declares `cipher = "0.4"` for the `cbc` crate.
// Cargo allows both versions to coexist, but we can't import cipher 0.5 traits
// directly since the `cipher` dependency resolves to 0.4. Instead, we access
// the cipher 0.5 traits through `magma`'s public re-export. If `magma` ever
// changes its re-exports, this import path will need updating for all cipher 0.5
// ciphers simultaneously.
macro_rules! cipher05_cbc_impl {
    ($cipher:ty, $key_len:expr, $block_size:expr) => {{
        use magma::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};

        fn enc(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
            if key.len() != $key_len {
                return Err(CryptoError::InvalidKeyLength {
                    expected: $key_len,
                    got: key.len(),
                });
            }
            let cipher = <$cipher>::new_from_slice(key)
                .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
            let mut iv = [0u8; $block_size];
            rand::rng().fill_bytes(&mut iv);
            let padding_len = $block_size - (plaintext.len() % $block_size);
            let mut buffer = vec![padding_len as u8; plaintext.len() + padding_len];
            buffer[..plaintext.len()].copy_from_slice(plaintext);
            let mut prev = iv;
            for chunk in buffer.chunks_mut($block_size) {
                for (i, b) in chunk.iter_mut().enumerate() {
                    *b ^= prev[i];
                }
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
            if key.len() != $key_len {
                return Err(CryptoError::InvalidKeyLength {
                    expected: $key_len,
                    got: key.len(),
                });
            }
            if ciphertext.len() < $block_size {
                return Err(CryptoError::InvalidNonce);
            }
            let cipher = <$cipher>::new_from_slice(key)
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
            let (iv, data) = ciphertext.split_at($block_size);
            // Validate ciphertext length is non-empty and multiple of block size
            if data.is_empty() || data.len() % $block_size != 0 {
                return Err(CryptoError::DecryptionFailed(
                    "Invalid ciphertext length".into(),
                ));
            }
            let mut buffer = data.to_vec();
            let mut prev = [0u8; $block_size];
            prev.copy_from_slice(iv);
            for chunk in buffer.chunks_mut($block_size) {
                let mut ct_backup = [0u8; $block_size];
                ct_backup.copy_from_slice(chunk);
                let mut block = (*<&[u8; $block_size]>::try_from(&chunk[..]).unwrap()).into();
                cipher.decrypt_block(&mut block);
                chunk.copy_from_slice(&block);
                for (i, b) in chunk.iter_mut().enumerate() {
                    *b ^= prev[i];
                }
                prev = ct_backup;
            }
            let last_byte = *buffer
                .last()
                .ok_or_else(|| CryptoError::DecryptionFailed("Empty".into()))?;
            let padding_len = last_byte as usize;

            // Fully constant-time padding validation.
            // Always examines exactly $block_size bytes to prevent leaking
            // the padding value via timing.
            let block_size: usize = $block_size;
            let valid = ((padding_len >= 1) as u8) & ((padding_len <= block_size) as u8);
            let mut bad = valid ^ 1;

            let check_start = buffer.len() - block_size;
            let threshold = block_size.saturating_sub(padding_len);
            for i in 0..block_size {
                let in_pad = ((i >= threshold) as u8) & valid;
                bad |= in_pad & (buffer[check_start + i] ^ last_byte);
            }

            if bad != 0 {
                return Err(CryptoError::DecryptionFailed("Invalid padding".into()));
            }
            buffer.truncate(buffer.len() - padding_len);
            Ok(buffer)
        }

        (enc as CipherFn, dec as CipherFn)
    }};
}

fn ascon_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use ascon_aead::{
        aead::{Aead, KeyInit},
        AsconAead128,
    };
    const KEY_LEN: usize = 16;
    const NONCE_SIZE: usize = 16;
    let key_arr: [u8; KEY_LEN] = key.try_into().map_err(|_| CryptoError::InvalidKeyLength {
        expected: KEY_LEN,
        got: key.len(),
    })?;
    let cipher = AsconAead128::new(&key_arr.into());
    let mut nonce = [0u8; NONCE_SIZE];
    rand::rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(&nonce.into(), plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    let mut result = Vec::with_capacity(NONCE_SIZE + ct.len());
    result.extend_from_slice(&nonce);
    result.extend(ct);
    Ok(result)
}

fn ascon_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use ascon_aead::{
        aead::{Aead, KeyInit},
        AsconAead128,
    };
    const KEY_LEN: usize = 16;
    const NONCE_SIZE: usize = 16;
    if ciphertext.len() < NONCE_SIZE {
        return Err(CryptoError::InvalidNonce);
    }
    let key_arr: [u8; KEY_LEN] = key.try_into().map_err(|_| CryptoError::InvalidKeyLength {
        expected: KEY_LEN,
        got: key.len(),
    })?;
    let cipher = AsconAead128::new(&key_arr.into());
    let (nonce, data) = ciphertext.split_at(NONCE_SIZE);
    let nonce_arr: [u8; NONCE_SIZE] = nonce.try_into().map_err(|_| CryptoError::InvalidNonce)?;
    cipher
        .decrypt(&nonce_arr.into(), data)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

#[must_use = "encrypted data must be used"]
pub fn encrypt(algo: Algorithm, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let (enc, _) = get_cipher_fns(algo);
    enc(key, plaintext)
}

#[must_use = "decrypted data must be used"]
pub fn decrypt(algo: Algorithm, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let (_, dec) = get_cipher_fns(algo);
    dec(key, ciphertext)
}

fn get_cipher_fns(algo: Algorithm) -> (CipherFn, CipherFn) {
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
        Algorithm::Threefish256 => cipher05_cbc_impl!(threefish::Threefish256, 32, 32),
        Algorithm::Rc6 => cipher05_cbc_impl!(rc6::RC6_32_20_16, 16, 16),
        Algorithm::Magma => cipher05_cbc_impl!(magma::Magma, 32, 8),
        Algorithm::Speck128_256 => cipher05_cbc_impl!(speck_cipher::Speck128_256, 32, 16),
        Algorithm::Gift128 => cipher05_cbc_impl!(gift_cipher::Gift128, 16, 16),
        Algorithm::Ascon128 => (ascon_encrypt, ascon_decrypt),
    }
}

// --- Mmap-backed in-place decrypt (K-2 fix) ---
// Parallel to the CipherFn-based decrypt path. These write plaintext directly
// into a caller-provided output buffer (backed by mmap) instead of returning
// Vec<u8>, avoiding the per-layer RAM allocation that causes OOM on large files.

pub(crate) type MmapDecryptFn =
    fn(key: &[u8], input: &[u8], output: &mut [u8]) -> Result<usize, CryptoError>;

fn validate_pkcs7_ct(buffer: &[u8], block_size: usize) -> Result<usize, CryptoError> {
    let last_byte = *buffer
        .last()
        .ok_or_else(|| CryptoError::DecryptionFailed("Empty".into()))?;
    let padding_len = last_byte as usize;
    let valid = ((padding_len >= 1) as u8) & ((padding_len <= block_size) as u8);
    let mut bad = valid ^ 1;
    let check_start = buffer.len() - block_size;
    let threshold = block_size.saturating_sub(padding_len);
    for i in 0..block_size {
        let in_pad = ((i >= threshold) as u8) & valid;
        bad |= in_pad & (buffer[check_start + i] ^ last_byte);
    }
    if bad != 0 {
        return Err(CryptoError::DecryptionFailed("Invalid padding".into()));
    }
    Ok(padding_len)
}

macro_rules! cbc_mmap_dec {
    ($cipher:ty, $key_len:expr, $block_size:expr, $iv_size:expr) => {{
        use cbc::Decryptor;
        use cipher::{BlockDecryptMut, KeyIvInit};

        fn dec_mmap(key: &[u8], input: &[u8], output: &mut [u8]) -> Result<usize, CryptoError> {
            if key.len() != $key_len {
                return Err(CryptoError::InvalidKeyLength { expected: $key_len, got: key.len() });
            }
            if input.len() < $iv_size + $block_size {
                return Err(CryptoError::InvalidNonce);
            }
            let (iv, data) = input.split_at($iv_size);
            if data.is_empty() || data.len() % $block_size != 0 {
                return Err(CryptoError::DecryptionFailed("Invalid ciphertext length".into()));
            }
            output[..data.len()].copy_from_slice(data);
            Decryptor::<$cipher>::new_from_slices(key, iv)
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?
                .decrypt_padded_mut::<block_padding::NoPadding>(&mut output[..data.len()])
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
            let pad = validate_pkcs7_ct(&output[..data.len()], $block_size)?;
            Ok(data.len() - pad)
        }
        dec_mmap as MmapDecryptFn
    }};
}

macro_rules! aead_mmap_dec {
    ($cipher:ty, $nonce_size:expr) => {{
        use aes_gcm::aead::{
            generic_array::{typenum::Unsigned, GenericArray},
            AeadCore, AeadInPlace, KeyInit,
        };

        fn dec_mmap(key: &[u8], input: &[u8], output: &mut [u8]) -> Result<usize, CryptoError> {
            // Derive tag length from the cipher's associated type so a future
            // AEAD with a different tag size stays correct without touching this code.
            let tag_len = <<$cipher as AeadCore>::TagSize as Unsigned>::USIZE;
            if key.len() != 32 {
                return Err(CryptoError::InvalidKeyLength { expected: 32, got: key.len() });
            }
            if input.len() < $nonce_size + tag_len {
                return Err(CryptoError::InvalidNonce);
            }
            let (nonce, rest) = input.split_at($nonce_size);
            let ct_len = rest.len() - tag_len;
            let (ct, tag) = rest.split_at(ct_len);
            output[..ct_len].copy_from_slice(ct);
            <$cipher>::new_from_slice(key)
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?
                .decrypt_in_place_detached(
                    GenericArray::from_slice(nonce),
                    &[],
                    &mut output[..ct_len],
                    GenericArray::from_slice(tag),
                )
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
            Ok(ct_len)
        }
        dec_mmap as MmapDecryptFn
    }};
}

macro_rules! cipher05_cbc_mmap_dec {
    ($cipher:ty, $key_len:expr, $block_size:expr) => {{
        use magma::cipher::{BlockCipherDecrypt, KeyInit};

        fn dec_mmap(key: &[u8], input: &[u8], output: &mut [u8]) -> Result<usize, CryptoError> {
            if key.len() != $key_len {
                return Err(CryptoError::InvalidKeyLength { expected: $key_len, got: key.len() });
            }
            if input.len() < $block_size * 2 {
                return Err(CryptoError::InvalidNonce);
            }
            let (iv, data) = input.split_at($block_size);
            if data.is_empty() || data.len() % $block_size != 0 {
                return Err(CryptoError::DecryptionFailed("Invalid ciphertext length".into()));
            }
            output[..data.len()].copy_from_slice(data);
            let cipher = <$cipher>::new_from_slice(key)
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
            let mut prev = [0u8; $block_size];
            prev.copy_from_slice(iv);
            for chunk in output[..data.len()].chunks_mut($block_size) {
                let mut ct_backup = [0u8; $block_size];
                ct_backup.copy_from_slice(chunk);
                let mut block = (*<&[u8; $block_size]>::try_from(&chunk[..]).unwrap()).into();
                cipher.decrypt_block(&mut block);
                chunk.copy_from_slice(&block);
                for (i, b) in chunk.iter_mut().enumerate() {
                    *b ^= prev[i];
                }
                prev = ct_backup;
            }
            let pad = validate_pkcs7_ct(&output[..data.len()], $block_size)?;
            Ok(data.len() - pad)
        }
        dec_mmap as MmapDecryptFn
    }};
}

#[allow(deprecated)]
fn ascon_decrypt_mmap(key: &[u8], input: &[u8], output: &mut [u8]) -> Result<usize, CryptoError> {
    use ascon_aead::{
        aead::{AeadInPlace, KeyInit},
        AsconAead128,
    };
    const KEY_LEN: usize = 16;
    const NONCE_SIZE: usize = 16;
    const TAG_LEN: usize = 16;
    if input.len() < NONCE_SIZE + TAG_LEN {
        return Err(CryptoError::InvalidNonce);
    }
    let key_arr: [u8; KEY_LEN] = key.try_into().map_err(|_| CryptoError::InvalidKeyLength {
        expected: KEY_LEN,
        got: key.len(),
    })?;
    let (nonce, rest) = input.split_at(NONCE_SIZE);
    let ct_len = rest.len() - TAG_LEN;
    let (ct, tag) = rest.split_at(ct_len);
    let nonce_arr: [u8; NONCE_SIZE] = nonce.try_into().map_err(|_| CryptoError::InvalidNonce)?;
    let tag_arr: [u8; TAG_LEN] = tag.try_into().map_err(|_| CryptoError::InvalidNonce)?;
    output[..ct_len].copy_from_slice(ct);
    AsconAead128::new(&key_arr.into())
        .decrypt_in_place_detached(
            &nonce_arr.into(),
            &[],
            &mut output[..ct_len],
            &tag_arr.into(),
        )
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
    Ok(ct_len)
}

pub(crate) fn decrypt_mmap(
    algo: Algorithm,
    key: &[u8],
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, CryptoError> {
    let f = get_mmap_decrypt_fn(algo);
    f(key, input, output)
}

fn get_mmap_decrypt_fn(algo: Algorithm) -> MmapDecryptFn {
    match algo {
        Algorithm::Aes256 => aead_mmap_dec!(aes_gcm::Aes256Gcm, 12),
        Algorithm::ChaCha20Poly1305 => aead_mmap_dec!(chacha20poly1305::ChaCha20Poly1305, 12),
        Algorithm::XChaCha20Poly1305 => aead_mmap_dec!(chacha20poly1305::XChaCha20Poly1305, 24),
        Algorithm::TripleDes => cbc_mmap_dec!(des::TdesEde3, 24, 8, 8),
        Algorithm::Twofish => cbc_mmap_dec!(twofish::Twofish, 32, 16, 16),
        Algorithm::Serpent => cbc_mmap_dec!(serpent::Serpent, 32, 16, 16),
        Algorithm::Camellia => cbc_mmap_dec!(camellia::Camellia256, 32, 16, 16),
        Algorithm::Blowfish => cbc_mmap_dec!(blowfish::Blowfish, 32, 8, 8),
        Algorithm::Cast5 => cbc_mmap_dec!(cast5::Cast5, 16, 8, 8),
        Algorithm::Idea => cbc_mmap_dec!(idea::Idea, 16, 8, 8),
        Algorithm::Aria => cbc_mmap_dec!(aria::Aria256, 32, 16, 16),
        Algorithm::Sm4 => cbc_mmap_dec!(sm4::Sm4, 16, 16, 16),
        Algorithm::Kuznyechik => cbc_mmap_dec!(kuznyechik::Kuznyechik, 32, 16, 16),
        Algorithm::Seed => cbc_mmap_dec!(kisaseed::SEED, 16, 16, 16),
        Algorithm::Threefish256 => cipher05_cbc_mmap_dec!(threefish::Threefish256, 32, 32),
        Algorithm::Rc6 => cipher05_cbc_mmap_dec!(rc6::RC6_32_20_16, 16, 16),
        Algorithm::Magma => cipher05_cbc_mmap_dec!(magma::Magma, 32, 8),
        Algorithm::Speck128_256 => cipher05_cbc_mmap_dec!(speck_cipher::Speck128_256, 32, 16),
        Algorithm::Gift128 => cipher05_cbc_mmap_dec!(gift_cipher::Gift128, 16, 16),
        Algorithm::Ascon128 => ascon_decrypt_mmap,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_roundtrip(algo: Algorithm) {
        let key = vec![0x42u8; algo.key_size()];
        let plaintext = b"Hello, cascrypt!";
        let encrypted = encrypt(algo, &key, plaintext).unwrap();
        let decrypted = decrypt(algo, &key, &encrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_aes256() {
        test_roundtrip(Algorithm::Aes256);
    }
    #[test]
    fn test_tripledes() {
        test_roundtrip(Algorithm::TripleDes);
    }
    #[test]
    fn test_twofish() {
        test_roundtrip(Algorithm::Twofish);
    }
    #[test]
    fn test_serpent() {
        test_roundtrip(Algorithm::Serpent);
    }
    #[test]
    fn test_chacha20() {
        test_roundtrip(Algorithm::ChaCha20Poly1305);
    }
    #[test]
    fn test_xchacha20() {
        test_roundtrip(Algorithm::XChaCha20Poly1305);
    }
    #[test]
    fn test_camellia() {
        test_roundtrip(Algorithm::Camellia);
    }
    #[test]
    fn test_blowfish() {
        test_roundtrip(Algorithm::Blowfish);
    }
    #[test]
    fn test_cast5() {
        test_roundtrip(Algorithm::Cast5);
    }
    #[test]
    fn test_idea() {
        test_roundtrip(Algorithm::Idea);
    }
    #[test]
    fn test_aria() {
        test_roundtrip(Algorithm::Aria);
    }
    #[test]
    fn test_sm4() {
        test_roundtrip(Algorithm::Sm4);
    }
    #[test]
    fn test_kuznyechik() {
        test_roundtrip(Algorithm::Kuznyechik);
    }
    #[test]
    fn test_seed() {
        test_roundtrip(Algorithm::Seed);
    }
    #[test]
    fn test_threefish256() {
        test_roundtrip(Algorithm::Threefish256);
    }
    #[test]
    fn test_rc6() {
        test_roundtrip(Algorithm::Rc6);
    }
    #[test]
    fn test_magma() {
        test_roundtrip(Algorithm::Magma);
    }
    #[test]
    fn test_speck128_256() {
        test_roundtrip(Algorithm::Speck128_256);
    }
    #[test]
    fn test_gift128() {
        test_roundtrip(Algorithm::Gift128);
    }
    #[test]
    fn test_ascon128() {
        test_roundtrip(Algorithm::Ascon128);
    }

    #[test]
    fn test_different_nonces() {
        let key = [0x42u8; 32];
        let plaintext = b"Same plaintext";
        let e1 = encrypt(Algorithm::Aes256, &key, plaintext).unwrap();
        let e2 = encrypt(Algorithm::Aes256, &key, plaintext).unwrap();
        assert_ne!(e1, e2);
    }

    #[test]
    fn test_truncated_ciphertext_returns_error() {
        // Verify truncated ciphertext returns error instead of panicking.
        // This tests the cipher05_cbc_impl ciphers which had a panic bug.
        let algos = [
            (Algorithm::Threefish256, 32usize),
            (Algorithm::Rc6, 16),
            (Algorithm::Magma, 32),
            (Algorithm::Speck128_256, 32),
            (Algorithm::Gift128, 16),
        ];
        for (algo, key_size) in algos {
            let key = vec![0x42u8; key_size];
            let plaintext = b"Test data";
            let encrypted = encrypt(algo, &key, plaintext).unwrap();
            // Truncate to leave partial block (IV + partial data)
            let truncated = &encrypted[..encrypted.len() - 3];
            let result = decrypt(algo, &key, truncated);
            assert!(
                result.is_err(),
                "{:?} should error on truncated ciphertext",
                algo
            );
        }
    }
}
