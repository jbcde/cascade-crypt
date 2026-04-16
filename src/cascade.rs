use argon2::Argon2;
use rand::Rng;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::buffer::{
    process_mmap, should_switch_to_disk, transform_in_place_mmap, BufferMode, LayerBuffer,
    ProcessError, SecureTempFile,
};
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
    pub fn _x_byte(b: u8) -> u8 {
        _f(b)
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

/// Mmap-backed cascade decrypt for large non-chunked files (K-2 fix).
///
/// Takes a `SecureTempFile` already populated with the ciphertext body (hash
/// verified by the caller). Runs each cipher layer by mmap'ing the current
/// working file read-only as input and a second temp file read-write as output,
/// invoking `crypto::decrypt_mmap` which writes plaintext directly into the
/// output mapping. After each layer the files are swapped and the source is
/// wiped.
///
/// Returns the temp file containing the final layer's output — this is still
/// base64-encoded plaintext (the encoder layer hasn't been reversed). The
/// caller is responsible for UTF-8 validation, puzzle-lock reversal is handled
/// here if `header.locked`, and base64 decoding to the output sink.
pub fn decrypt_layers_mmap<F>(
    header: &Header,
    ciphertext_file: SecureTempFile,
    password: &[u8],
    mut progress: F,
) -> Result<SecureTempFile, CascadeError>
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

    let mut current = ciphertext_file;
    let mut next = SecureTempFile::new().map_err(CascadeError::Io)?;

    for (i, algo) in header.algorithms.iter().rev().enumerate() {
        let key_index = total - 1 - i;
        let key_bytes: &[u8] = keys[key_index].as_ref();
        let algo_copy = *algo;

        process_mmap(&mut current, &mut next, |input, output| {
            crypto::decrypt_mmap(algo_copy, key_bytes, input, output)
        })
        .map_err(|e| match e {
            ProcessError::Io(io) => CascadeError::Io(io),
            ProcessError::Crypto(c) => CascadeError::Crypto(c),
        })?;

        std::mem::swap(&mut current, &mut next);
        progress(i + 1, total);
    }

    if header.locked {
        transform_in_place_mmap(&mut current, _t::_x_byte).map_err(CascadeError::Io)?;
    }

    Ok(current)
}

/// Top-level mmap-backed decrypt for large non-chunked files (K-2 fix).
///
/// Bounded RAM regardless of file size. Callers should route here when
/// `file_size > available_memory / 2`.
///
/// Pipeline:
/// 1. Peek header (bounded 64 KiB read, K-4 cap applies)
/// 2. Parse header (v7 plaintext or v8 encrypted — the latter needs `private_key`)
/// 3. Stream body → `SecureTempFile`, verify SHA-256 incrementally
/// 4. Run `decrypt_layers_mmap` through the cipher cascade
/// 5. mmap the final layer's output; UTF-8 validate
/// 6. Stream base64 decode to `output`
pub fn decrypt_nonchunked_mmap<W, F>(
    input_path: &std::path::Path,
    output: &mut W,
    password: &[u8],
    private_key: Option<&HybridPrivateKey>,
    mut progress: F,
) -> Result<(), CascadeError>
where
    W: std::io::Write,
    F: FnMut(usize, usize),
{
    use std::fs::File;
    use std::io::{Cursor, Read, Seek, SeekFrom};

    let mut file = File::open(input_path).map_err(CascadeError::Io)?;

    // Peek: header line is capped at 64 KiB (K-4), so this is sufficient.
    let mut peek = vec![0u8; 65536];
    let n = file.read(&mut peek).map_err(CascadeError::Io)?;
    peek.truncate(n);

    // Parse header
    let (header, remaining) = if Header::is_encrypted(&peek) {
        let pk = private_key.ok_or(CascadeError::PrivateKeyRequired)?;
        Header::parse_encrypted(&peek, pk)?
    } else {
        Header::parse(&peek)?
    };
    let body_offset = (peek.len() - remaining.len()) as u64;

    // Stream body → temp file, compute SHA-256 incrementally
    file.seek(SeekFrom::Start(body_offset))
        .map_err(CascadeError::Io)?;
    let mut temp = SecureTempFile::new().map_err(CascadeError::Io)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 65536];
    loop {
        let n = file.read(&mut buf).map_err(CascadeError::Io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        temp.append(&buf[..n]).map_err(CascadeError::Io)?;
    }

    let computed: [u8; 32] = hasher.finalize().into();
    let expected = header.ciphertext_hash.ok_or_else(|| {
        CascadeError::Crypto(CryptoError::DecryptionFailed(
            "Missing ciphertext hash".into(),
        ))
    })?;
    if computed.ct_eq(&expected).unwrap_u8() != 1 {
        return Err(CascadeError::Crypto(CryptoError::DecryptionFailed(
            "Ciphertext hash mismatch".into(),
        )));
    }

    // Cipher cascade via mmap (bounded RAM per layer via page cache)
    let result_file = decrypt_layers_mmap(&header, temp, password, |i, t| progress(i, t))?;

    // mmap result, UTF-8 validate, stream-decode base64 to output.
    // SAFETY: we own the temp file; no external mutation during this call.
    let result_mmap = unsafe {
        memmap2::Mmap::map(result_file.file()).map_err(CascadeError::Io)?
    };
    std::str::from_utf8(&result_mmap).map_err(|_| {
        CascadeError::Crypto(CryptoError::DecryptionFailed(
            "Decryption failed - wrong password or corrupted data".into(),
        ))
    })?;

    encoder::decode_streaming(Cursor::new(&result_mmap[..]), output)
        .map_err(CascadeError::Io)?;

    Ok(())
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

    #[test]
    fn test_mmap_decrypt_roundtrip_mixed_cascade() {
        // K-2 regression: encrypt via the existing RAM path, then decrypt via
        // the mmap path and verify byte-identical roundtrip. Exercises the
        // mmap-in-place variants for both AEAD and CBC cipher families, and
        // the full decrypt_nonchunked_mmap pipeline (header parse → stream to
        // temp → hash verify → cascade via mmap → UTF-8 validate → streaming
        // base64 decode).
        use std::io::Write;

        let data: Vec<u8> = (0..=255u8).cycle().take(16 * 1024).collect();
        let password = random_password();
        let algorithms = vec![
            Algorithm::Aes256,           // AEAD via aead_mmap_dec
            Algorithm::Serpent,          // CBC via cbc_mmap_dec
            Algorithm::ChaCha20Poly1305, // AEAD
            Algorithm::Threefish256,     // cipher05 CBC via cipher05_cbc_mmap_dec
        ];

        let encrypted = encrypt(&data, &password, &algorithms).unwrap();

        let tmpdir = std::env::temp_dir();
        let input_path = tmpdir.join(format!(
            "cascrypt-mmap-test-{}.enc",
            rand::rng().random::<u64>()
        ));
        {
            let mut f = std::fs::File::create(&input_path).unwrap();
            f.write_all(&encrypted).unwrap();
        }

        let mut output = Vec::new();
        decrypt_nonchunked_mmap(&input_path, &mut output, &password, None, |_, _| {}).unwrap();

        let _ = std::fs::remove_file(&input_path);
        assert_eq!(data, output);
    }

    #[test]
    fn test_mmap_decrypt_protected_header_roundtrip() {
        // K-2 regression: v8-encoded non-chunked files with pubkey-protected
        // headers must decrypt correctly through the mmap path. Header parsing
        // goes through Header::parse_encrypted (hybrid X25519+ML-KEM decrypt)
        // before the cascade runs via mmap.
        use std::io::Write;

        let data: Vec<u8> = (0..=255u8).cycle().take(8 * 1024).collect();
        let password = random_password();
        let keypair = HybridKeypair::generate();

        // Encrypt with protected header
        let encrypted = encrypt_protected(
            &data,
            &password,
            &[Algorithm::Aes256, Algorithm::Serpent, Algorithm::ChaCha20Poly1305],
            &keypair.public,
            false,
        )
        .unwrap();
        assert!(Header::is_encrypted(&encrypted));

        let tmpdir = std::env::temp_dir();
        let input_path = tmpdir.join(format!(
            "cascrypt-mmap-protected-{}.enc",
            rand::rng().random::<u64>()
        ));
        {
            let mut f = std::fs::File::create(&input_path).unwrap();
            f.write_all(&encrypted).unwrap();
        }

        // Decrypt through the mmap path with the private key
        let mut output = Vec::new();
        decrypt_nonchunked_mmap(
            &input_path,
            &mut output,
            &password,
            Some(&keypair.private),
            |_, _| {},
        )
        .unwrap();

        let _ = std::fs::remove_file(&input_path);
        assert_eq!(data, output);
    }

    #[test]
    fn test_mmap_decrypt_protected_requires_privkey() {
        // Mmap path must refuse v8 files without a private key, matching the
        // RAM path's behavior.
        use std::io::Write;

        let data = b"protected content";
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

        let tmpdir = std::env::temp_dir();
        let input_path = tmpdir.join(format!(
            "cascrypt-mmap-protected-nokey-{}.enc",
            rand::rng().random::<u64>()
        ));
        {
            let mut f = std::fs::File::create(&input_path).unwrap();
            f.write_all(&encrypted).unwrap();
        }

        let mut output = Vec::new();
        let result = decrypt_nonchunked_mmap(&input_path, &mut output, &password, None, |_, _| {});

        let _ = std::fs::remove_file(&input_path);
        assert!(matches!(result, Err(CascadeError::PrivateKeyRequired)));
        assert!(output.is_empty());
    }

    #[test]
    fn test_mmap_decrypt_wrong_password_fails() {
        // Wrong password through the mmap path should fail at UTF-8 validation
        // or hash verification (garbage output), not silently emit garbage.
        use std::io::Write;

        let data = b"Content that should not leak on wrong password.".to_vec();
        let password = random_password();
        let wrong = random_password();

        let encrypted = encrypt(&data, &password, &[Algorithm::Aes256, Algorithm::Serpent]).unwrap();

        let tmpdir = std::env::temp_dir();
        let input_path = tmpdir.join(format!(
            "cascrypt-mmap-wrongpw-{}.enc",
            rand::rng().random::<u64>()
        ));
        {
            let mut f = std::fs::File::create(&input_path).unwrap();
            f.write_all(&encrypted).unwrap();
        }

        let mut output = Vec::new();
        let result = decrypt_nonchunked_mmap(&input_path, &mut output, &wrong, None, |_, _| {});

        let _ = std::fs::remove_file(&input_path);
        assert!(result.is_err(), "wrong password must not succeed");
        assert!(output.is_empty(), "no plaintext should be emitted on wrong password");
    }
}
