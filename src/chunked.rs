use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::buffer::BufferMode;
use crate::cascade::{decrypt_layers, encrypt_layers, CascadeError};
use crate::crypto::Algorithm;
use crate::header::{Argon2Params, Header, HeaderError};
use crate::hybrid::{HybridPrivateKey, HybridPublicKey};

const SALT_LEN: usize = 32;
const HMAC_LEN: usize = 32;
const FRAME_PREFIX_LEN: usize = 8; // u64 LE chunk length
/// Hard cap on a single chunk frame to prevent OOM from crafted frame_len.
/// 8 GiB is far beyond any reasonable chunk size.
const MAX_FRAME_LEN: u64 = 8 * 1024 * 1024 * 1024;
/// Maximum header size to prevent unbounded allocation from read_until.
const MAX_HEADER_LEN: usize = 64 * 1024;
/// Maximum chunk count to prevent sustained-compute DoS from attacker-controlled
/// headers. 2^40 (~1 trillion) covers any plausible file at any chunk size while
/// cutting the attacker's Argon2id workload ceiling by 24 bits vs u32::MAX (K-10).
const MAX_CHUNK_COUNT: u64 = 1 << 40;

/// Check whether a file should be chunked based on available RAM.
/// Returns `Some(chunk_size)` if the file exceeds the memory threshold, else `None`.
pub fn should_chunk(file_size: u64) -> Option<usize> {
    let available = crate::buffer::get_available_memory()?;
    compute_chunk_size(file_size, available as u64)
}

/// Pure decision logic: given file size and available memory, decide whether to
/// chunk and what size. Returns `Some(chunk_size)` if `file_size > 3/4 * available`,
/// with chunk_size = available / 4 (minimum 1 MiB).
fn compute_chunk_size(file_size: u64, available: u64) -> Option<usize> {
    if available == 0 {
        return None;
    }
    let threshold = (available * 3) / 4;
    if file_size > threshold {
        let chunk = (available / 4).max(1024 * 1024);
        Some(chunk as usize)
    } else {
        None
    }
}

/// Derive a per-file HMAC key from the password and file-level salt via HKDF-SHA256.
///
/// The file salt lives in the header and is covered by the header hash (v13) or
/// the authenticated encrypted payload (v14), so an attacker cannot substitute a
/// different file's salt without being detected. Binding the HMAC key to a
/// per-file random value prevents cross-file chunk splicing: a frame from file A
/// is not a valid frame in file B even when both share the same password.
fn derive_file_hmac_key(password: &[u8], file_salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(file_salt), password);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(b"cascrypt-file-hmac", key.as_mut())
        .expect("32 bytes is valid for HKDF-SHA256");
    key
}

/// Legacy per-chunk HMAC key derivation used by v11/v12 files (v0.7.0).
///
/// Files using this scheme are vulnerable to cross-file chunk splicing when the
/// same password is reused across files — see kelly-review.md K-1. Retained for
/// backward-compatible decryption of legacy files; never used on encryption.
fn derive_legacy_chunk_hmac_key(password: &[u8], chunk_salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(chunk_salt), password);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(b"cascrypt-chunk-hmac", key.as_mut())
        .expect("32 bytes is valid for HKDF-SHA256");
    key
}

/// Compute HMAC-SHA256 over chunk data, binding chunk index, frame length, salt, and ciphertext.
fn compute_chunk_hmac(
    key: &[u8; 32],
    chunk_index: u64,
    frame_len_bytes: &[u8],
    salt: &[u8],
    ciphertext: &[u8],
) -> [u8; 32] {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("32-byte key is valid for HMAC");
    mac.update(&chunk_index.to_le_bytes());
    mac.update(frame_len_bytes);
    mac.update(salt);
    mac.update(ciphertext);
    mac.finalize().into_bytes().into()
}

/// Read up to `buf.len()` bytes, retrying on partial reads until EOF.
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, CascadeError> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) => return Err(CascadeError::Io(e)),
        }
    }
    Ok(total)
}

/// Encrypt a file in chunks, writing framed output to a seekable writer.
///
/// Reads `chunk_size` bytes at a time from `input`, keeping memory proportional
/// to chunk size rather than file size.
///
/// Output format:
/// ```text
/// [header]\n
/// [8-byte LE frame_len][32-byte salt][ciphertext] × chunk_count
/// ```
pub fn encrypt_chunked<R, W, F>(
    input: &mut R,
    output: &mut W,
    password: &[u8],
    algorithms: &[Algorithm],
    chunk_size: usize,
    file_size: u64,
    locked: bool,
    buffer_mode: BufferMode,
    pubkey: Option<&HybridPublicKey>,
    mut progress: F,
) -> Result<(), CascadeError>
where
    R: Read,
    W: Write + Seek,
    F: FnMut(usize, usize),
{
    if algorithms.is_empty() {
        return Err(CascadeError::NoAlgorithms);
    }

    let chunk_count = if file_size == 0 {
        1usize
    } else {
        let count_u64 = (file_size + chunk_size as u64 - 1) / chunk_size as u64;
        usize::try_from(count_u64).map_err(|_| {
            CascadeError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Chunk count overflows usize",
            ))
        })?
    };

    // File-level salt: drives the per-file HMAC key, covered by the header hash
    // (v13) or the authenticated encrypted payload (v14). Generated once and held
    // stable across placeholder and final header writes.
    let file_salt: [u8; 32] = rand::rng().random();
    let hmac_key = derive_file_hmac_key(password, &file_salt);

    // Write placeholder header — we'll seek back to overwrite with final hash.
    // For encrypted headers (v14), the serialized size varies due to random
    // ephemeral keys producing JSON byte arrays of different decimal widths.
    // We pad the placeholder with extra space to guarantee the final header fits.
    let placeholder_header = Header::with_chunks(
        algorithms.to_vec(),
        file_salt,
        Argon2Params::default(),
        chunk_count as u64,
        [0u8; 32], // placeholder hash
    );
    let is_encrypted_header = pubkey.is_some();
    let header_str = if let Some(pk) = pubkey {
        placeholder_header.serialize_encrypted(pk)?
    } else {
        placeholder_header.serialize()
    };
    // For v10, add 1024 null bytes after the header to absorb size variance
    // on rewrite. The parser finds the first \n and ignores anything after it
    // until the chunk frames start at the reserved offset.
    let header_len = if is_encrypted_header {
        let padded_len = header_str.len() + 1024;
        let mut padded = header_str.into_bytes();
        padded.resize(padded_len, 0u8); // null padding after "]\n"
        output.write_all(&padded).map_err(CascadeError::Io)?;
        padded_len
    } else {
        let len = header_str.len();
        output
            .write_all(header_str.as_bytes())
            .map_err(CascadeError::Io)?;
        len
    };

    // Read and encrypt each chunk incrementally
    let mut hasher = Sha256::new();
    let mut buf = Zeroizing::new(vec![0u8; chunk_size]);
    for i in 0..chunk_count {
        let bytes_read = read_full(input, &mut buf)?;
        let chunk_data = &buf[..bytes_read];

        let salt: [u8; 32] = rand::rng().random();
        let ciphertext = encrypt_layers(
            chunk_data, password, algorithms, &salt, locked, buffer_mode, |_, _| {},
        )?;

        // Frame: [8-byte len][32-byte salt][32-byte hmac][ciphertext]
        let frame_len = (SALT_LEN + HMAC_LEN + ciphertext.len()) as u64;
        let frame_len_bytes = frame_len.to_le_bytes();

        let hmac_tag = compute_chunk_hmac(&hmac_key, i as u64, &frame_len_bytes, &salt, &ciphertext);

        output
            .write_all(&frame_len_bytes)
            .map_err(CascadeError::Io)?;
        output.write_all(&salt).map_err(CascadeError::Io)?;
        output.write_all(&hmac_tag).map_err(CascadeError::Io)?;
        output.write_all(&ciphertext).map_err(CascadeError::Io)?;

        hasher.update(&frame_len_bytes);
        hasher.update(&salt);
        hasher.update(&hmac_tag);
        hasher.update(&ciphertext);

        progress(i + 1, chunk_count);
    }

    // Compute final hash and rewrite header
    let full_hash: [u8; 32] = hasher.finalize().into();
    let final_header = Header::with_chunks(
        algorithms.to_vec(),
        file_salt,
        Argon2Params::default(),
        chunk_count as u64,
        full_hash,
    );
    let final_header_str = if let Some(pk) = pubkey {
        final_header.serialize_encrypted(pk)?
    } else {
        final_header.serialize()
    };

    // Seek to start and overwrite header
    output
        .seek(SeekFrom::Start(0))
        .map_err(CascadeError::Io)?;
    let mut final_bytes = final_header_str.into_bytes();
    if final_bytes.len() > header_len {
        return Err(CascadeError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Final header exceeds reserved space — this is a bug",
        )));
    }
    // Pad with null bytes after "]\n" to fill the reserved space exactly
    final_bytes.resize(header_len, 0u8);
    output.write_all(&final_bytes).map_err(CascadeError::Io)?;

    Ok(())
}

/// Decrypt a chunked file from a reader, writing plaintext chunks to the writer.
///
/// Reads frame-by-frame from `input`, keeping memory proportional to one chunk
/// at a time. Hash integrity is verified after all frames are processed.
///
/// If `output_path` is provided and hash verification fails, the output file
/// is deleted to avoid leaving unverified plaintext on disk.
pub fn decrypt_chunked<R, W, F>(
    input: &mut R,
    output: &mut W,
    password: &[u8],
    buffer_mode: BufferMode,
    private_key: Option<&HybridPrivateKey>,
    output_path: Option<&std::path::Path>,
    mut progress: F,
) -> Result<(), CascadeError>
where
    R: Read,
    W: Write,
    F: FnMut(usize, usize),
{
    // Read header line with bounded length to prevent DoS from missing newline
    let mut reader = BufReader::new(input);
    let mut header_bytes = Vec::with_capacity(4096);
    loop {
        let available = reader.fill_buf().map_err(CascadeError::Io)?;
        if available.is_empty() {
            return Err(CascadeError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF before header newline",
            )));
        }
        let newline_pos = available.iter().position(|&b| b == b'\n');
        let take = newline_pos.map(|p| p + 1).unwrap_or(available.len());
        header_bytes.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline_pos.is_some() {
            break;
        }
        if header_bytes.len() > MAX_HEADER_LEN {
            return Err(CascadeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Header exceeds {} bytes without newline", MAX_HEADER_LEN),
            )));
        }
    }

    // Parse header
    let (header, _) = if let Some(pk) = private_key {
        if Header::is_encrypted(&header_bytes) {
            Header::parse_encrypted(&header_bytes, pk)?
        } else {
            Header::parse(&header_bytes)?
        }
    } else {
        Header::parse(&header_bytes)?
    };

    let chunk_count_u64 = header.chunk_count.ok_or(HeaderError::InvalidFormat)?;
    if chunk_count_u64 == 0 || chunk_count_u64 > MAX_CHUNK_COUNT {
        return Err(CascadeError::Crypto(
            crate::crypto::CryptoError::DecryptionFailed(
                format!("Invalid chunk count: {} (max {})", chunk_count_u64, MAX_CHUNK_COUNT),
            ),
        ));
    }
    let chunk_count = chunk_count_u64 as usize;

    // Derive the per-file HMAC key once from the header's file-level salt.
    // Every chunk HMAC in this file is keyed with this value, so frames from
    // other files (with different file salts) cannot be spliced in.
    //
    // Legacy v11/v12 files use per-chunk HMAC keys — derive inside the loop
    // from each chunk's own salt when header.legacy_chunk_hmac is set.
    let file_hmac_key = if header.legacy_chunk_hmac {
        None
    } else {
        Some(derive_file_hmac_key(password, &header.salt))
    };

    // Skip null padding after header (v10 encrypted headers use padding
    // to reserve fixed space for the header rewrite)
    loop {
        let buf = reader.fill_buf().map_err(CascadeError::Io)?;
        if buf.is_empty() {
            break;
        }
        let skip = buf.iter().take_while(|&&b| b == 0).count();
        if skip == 0 {
            break;
        }
        reader.consume(skip);
    }

    // Compute runtime frame size cap: the lesser of MAX_FRAME_LEN and available memory.
    // Prevents attacker-controlled frame_len from allocating more than the machine can handle.
    let frame_cap = crate::buffer::get_available_memory()
        .map(|mem| (mem as u64).min(MAX_FRAME_LEN))
        .unwrap_or(MAX_FRAME_LEN);

    // Single-pass: read, hash, and decrypt each frame
    let mut hasher = Sha256::new();
    for i in 0..chunk_count {
        // Read frame length prefix
        let mut frame_len_bytes = [0u8; FRAME_PREFIX_LEN];
        reader
            .read_exact(&mut frame_len_bytes)
            .map_err(CascadeError::Io)?;
        let frame_len_u64 = u64::from_le_bytes(frame_len_bytes);

        if frame_len_u64 < (SALT_LEN + HMAC_LEN) as u64 {
            return Err(CascadeError::Crypto(
                crate::crypto::CryptoError::DecryptionFailed(
                    "Chunk frame too small for salt + HMAC".into(),
                ),
            ));
        }
        if frame_len_u64 > frame_cap {
            return Err(CascadeError::Crypto(
                crate::crypto::CryptoError::DecryptionFailed(
                    format!("Chunk frame too large: {} bytes (max {})", frame_len_u64, frame_cap),
                ),
            ));
        }
        let frame_len = frame_len_u64 as usize;

        // Read frame data (salt + ciphertext)
        let mut frame_data = vec![0u8; frame_len];
        reader
            .read_exact(&mut frame_data)
            .map_err(CascadeError::Io)?;

        // Hash the frame prefix + frame data
        hasher.update(&frame_len_bytes);
        hasher.update(&frame_data);

        // Extract salt, HMAC tag, and ciphertext
        let salt: [u8; 32] = frame_data[..SALT_LEN].try_into().unwrap();
        let stored_hmac: [u8; 32] = frame_data[SALT_LEN..SALT_LEN + HMAC_LEN].try_into().unwrap();
        let ciphertext = &frame_data[SALT_LEN + HMAC_LEN..];

        // Verify HMAC BEFORE decrypting — reject tampered chunks without emitting plaintext.
        // v13/v14 uses the per-file key; v11/v12 legacy derives a per-chunk key.
        let expected_hmac = match &file_hmac_key {
            Some(key) => compute_chunk_hmac(key, i as u64, &frame_len_bytes, &salt, ciphertext),
            None => {
                let legacy_key = derive_legacy_chunk_hmac_key(password, &salt);
                compute_chunk_hmac(&legacy_key, i as u64, &frame_len_bytes, &salt, ciphertext)
            }
        };
        if stored_hmac.ct_eq(&expected_hmac).unwrap_u8() != 1 {
            if let Some(path) = output_path {
                let _ = std::fs::remove_file(path);
            }
            return Err(CascadeError::Crypto(
                crate::crypto::CryptoError::DecryptionFailed(
                    format!("Chunk {} HMAC verification failed — data may be tampered", i),
                ),
            ));
        }

        // Build per-chunk header for decrypt_layers
        let chunk_header = Header {
            algorithms: header.algorithms.clone(),
            salt,
            locked: header.locked,
            ciphertext_hash: None, // already verified at frame level
            argon2_params: header.argon2_params,
            chunk_count: None,
            legacy_chunk_hmac: false,
        };

        let decrypted =
            decrypt_layers(&chunk_header, ciphertext, password, buffer_mode, |_, _| {})?;

        output.write_all(&decrypted).map_err(CascadeError::Io)?;
        progress(i + 1, chunk_count);
    }

    // Verify full hash over all frame bytes
    let computed_hash: [u8; 32] = hasher.finalize().into();
    let expected_hash = header
        .ciphertext_hash
        .ok_or(HeaderError::MissingCiphertextHash)?;
    if computed_hash.ct_eq(&expected_hash).unwrap_u8() != 1 {
        // Delete output file to avoid leaving unverified plaintext on disk
        if let Some(path) = output_path {
            let _ = std::fs::remove_file(path);
        }
        return Err(CascadeError::Header(HeaderError::CiphertextHashMismatch));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // --- compute_chunk_size tests (pure logic, no platform dependency) ---

    #[test]
    fn test_compute_no_chunk_when_file_fits() {
        // 1 GiB file, 8 GiB RAM → threshold is 6 GiB → no chunking
        let ram = 8 * 1024 * 1024 * 1024u64;
        assert_eq!(compute_chunk_size(1 * 1024 * 1024 * 1024, ram), None);
    }

    #[test]
    fn test_compute_no_chunk_at_threshold_boundary() {
        // File exactly at 3/4 of RAM → not above threshold → no chunking
        let ram = 8 * 1024 * 1024 * 1024u64;
        let threshold = (ram * 3) / 4;
        assert_eq!(compute_chunk_size(threshold, ram), None);
    }

    #[test]
    fn test_compute_chunks_above_threshold() {
        // File 1 byte above 3/4 of RAM → should chunk
        let ram = 8 * 1024 * 1024 * 1024u64;
        let threshold = (ram * 3) / 4;
        let result = compute_chunk_size(threshold + 1, ram);
        assert!(result.is_some());
        // Chunk size should be RAM / 4
        assert_eq!(result.unwrap(), (ram / 4) as usize);
    }

    #[test]
    fn test_compute_chunk_size_is_quarter_ram() {
        let ram = 32 * 1024 * 1024 * 1024u64; // 32 GiB
        let file = 30 * 1024 * 1024 * 1024u64; // 30 GiB
        let result = compute_chunk_size(file, ram).unwrap();
        assert_eq!(result, 8 * 1024 * 1024 * 1024); // 8 GiB
    }

    #[test]
    fn test_compute_minimum_chunk_size_1mib() {
        // Very low RAM: 2 MiB → chunk size would be 512 KiB, but minimum is 1 MiB
        let ram = 2 * 1024 * 1024u64;
        let file = 10 * 1024 * 1024u64;
        let result = compute_chunk_size(file, ram).unwrap();
        assert_eq!(result, 1024 * 1024); // 1 MiB minimum
    }

    #[test]
    fn test_compute_zero_available_memory() {
        assert_eq!(compute_chunk_size(1000, 0), None);
    }

    #[test]
    fn test_compute_file_larger_than_ram() {
        // 100 GiB file, 4 GiB RAM
        let ram = 4 * 1024 * 1024 * 1024u64;
        let file = 100 * 1024 * 1024 * 1024u64;
        let result = compute_chunk_size(file, ram).unwrap();
        assert_eq!(result, 1 * 1024 * 1024 * 1024); // 1 GiB chunks
    }

    #[test]
    fn test_compute_tiny_file_never_chunks() {
        // 100 bytes, 1 GiB RAM → never chunk
        let ram = 1024 * 1024 * 1024u64;
        assert_eq!(compute_chunk_size(100, ram), None);
    }

    #[test]
    fn test_compute_zero_file_size() {
        let ram = 8 * 1024 * 1024 * 1024u64;
        assert_eq!(compute_chunk_size(0, ram), None);
    }

    #[test]
    fn test_compute_file_equals_ram() {
        // File == RAM → above 3/4 threshold → should chunk
        let ram = 4 * 1024 * 1024 * 1024u64;
        let result = compute_chunk_size(ram, ram);
        assert!(result.is_some());
    }

    // --- get_available_memory platform sanity test ---

    #[test]
    fn test_get_available_memory_returns_sane_value() {
        let mem = crate::buffer::get_available_memory();
        // Must return Some on Linux/macOS/Windows, None on other platforms
        if cfg!(any(target_os = "linux", target_os = "macos", target_os = "windows")) {
            let bytes = mem.expect("get_available_memory should return Some on this platform");
            // Sanity: more than 1 MiB, less than 1 TiB
            assert!(bytes > 1024 * 1024, "available memory suspiciously low: {} bytes", bytes);
            assert!(bytes < 1024 * 1024 * 1024 * 1024, "available memory suspiciously high: {} bytes", bytes);
        }
    }

    // --- should_chunk integration test ---

    #[test]
    fn test_should_chunk_small_file() {
        // A 1 KiB file should never trigger auto-chunking on any real machine
        assert_eq!(should_chunk(1024), None);
    }

    fn random_password() -> Vec<u8> {
        let bytes: [u8; 16] = rand::rng().random();
        bytes.to_vec()
    }

    #[test]
    fn test_chunked_roundtrip_small_chunks() {
        let data = b"Hello, this is a test of chunked encryption with small chunks!";
        let password = random_password();
        let algorithms = vec![Algorithm::Aes256];

        // Encrypt
        let mut input = Cursor::new(data.as_slice());
        let mut encrypted = Cursor::new(Vec::new());
        encrypt_chunked(
            &mut input,
            &mut encrypted,
            &password,
            &algorithms,
            16, // 16-byte chunks
            data.len() as u64,
            false,
            BufferMode::Ram,
            None,
            |_, _| {},
        )
        .unwrap();

        // Decrypt
        let encrypted_bytes = encrypted.into_inner();
        let mut reader = Cursor::new(encrypted_bytes.as_slice());
        let mut decrypted = Vec::new();
        decrypt_chunked(
            &mut reader,
            &mut decrypted,
            &password,
            BufferMode::Ram,
            None,
            None,
            |_, _| {},
        )
        .unwrap();

        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_chunked_single_chunk() {
        let data = b"Small data";
        let password = random_password();
        let algorithms = vec![Algorithm::Aes256, Algorithm::Serpent];

        let mut input = Cursor::new(data.as_slice());
        let mut encrypted = Cursor::new(Vec::new());
        encrypt_chunked(
            &mut input,
            &mut encrypted,
            &password,
            &algorithms,
            1024, // chunk size larger than data
            data.len() as u64,
            false,
            BufferMode::Ram,
            None,
            |_, _| {},
        )
        .unwrap();

        let encrypted_bytes = encrypted.into_inner();
        // Verify it's a v9 header
        assert!(Header::is_chunked(&encrypted_bytes));

        let mut reader = Cursor::new(encrypted_bytes.as_slice());
        let mut decrypted = Vec::new();
        decrypt_chunked(
            &mut reader,
            &mut decrypted,
            &password,
            BufferMode::Ram,
            None,
            None,
            |_, _| {},
        )
        .unwrap();

        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_chunked_binary_data() {
        let data: Vec<u8> = (0..=255).cycle().take(1000).collect();
        let password = random_password();
        let algorithms = vec![Algorithm::ChaCha20Poly1305];

        let mut input = Cursor::new(data.as_slice());
        let mut encrypted = Cursor::new(Vec::new());
        encrypt_chunked(
            &mut input,
            &mut encrypted,
            &password,
            &algorithms,
            100,
            data.len() as u64,
            false,
            BufferMode::Ram,
            None,
            |_, _| {},
        )
        .unwrap();

        let encrypted_bytes = encrypted.into_inner();
        let mut reader = Cursor::new(encrypted_bytes.as_slice());
        let mut decrypted = Vec::new();
        decrypt_chunked(
            &mut reader,
            &mut decrypted,
            &password,
            BufferMode::Ram,
            None,
            None,
            |_, _| {},
        )
        .unwrap();

        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_chunked_tamper_detection() {
        let data = b"Tamper test data for chunked encryption";
        let password = random_password();
        let algorithms = vec![Algorithm::Aes256];

        let mut input = Cursor::new(data.as_slice());
        let mut encrypted = Cursor::new(Vec::new());
        encrypt_chunked(
            &mut input,
            &mut encrypted,
            &password,
            &algorithms,
            16,
            data.len() as u64,
            false,
            BufferMode::Ram,
            None,
            |_, _| {},
        )
        .unwrap();

        let mut encrypted_bytes = encrypted.into_inner();
        // Tamper with last byte
        let len = encrypted_bytes.len();
        encrypted_bytes[len - 1] ^= 0xFF;

        let mut reader = Cursor::new(encrypted_bytes.as_slice());
        let mut decrypted = Vec::new();
        let result = decrypt_chunked(
            &mut reader,
            &mut decrypted,
            &password,
            BufferMode::Ram,
            None,
            None,
            |_, _| {},
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_chunked_wrong_password() {
        let data = b"Wrong password test";
        let password = random_password();
        let wrong_password = random_password();
        let algorithms = vec![Algorithm::Aes256];

        let mut input = Cursor::new(data.as_slice());
        let mut encrypted = Cursor::new(Vec::new());
        encrypt_chunked(
            &mut input,
            &mut encrypted,
            &password,
            &algorithms,
            16,
            data.len() as u64,
            false,
            BufferMode::Ram,
            None,
            |_, _| {},
        )
        .unwrap();

        let encrypted_bytes = encrypted.into_inner();
        let mut reader = Cursor::new(encrypted_bytes.as_slice());
        let mut decrypted = Vec::new();
        let result = decrypt_chunked(
            &mut reader,
            &mut decrypted,
            &wrong_password,
            BufferMode::Ram,
            None,
            None,
            |_, _| {},
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_chunked_encrypted_header_roundtrip() {
        use crate::hybrid::HybridKeypair;

        let data = b"Chunked encryption with v10 encrypted header";
        let password = random_password();
        let algorithms = vec![Algorithm::Aes256, Algorithm::ChaCha20Poly1305];
        let keypair = HybridKeypair::generate();

        let mut input = Cursor::new(data.as_slice());
        let mut encrypted = Cursor::new(Vec::new());
        encrypt_chunked(
            &mut input,
            &mut encrypted,
            &password,
            &algorithms,
            16,
            data.len() as u64,
            false,
            BufferMode::Ram,
            Some(&keypair.public),
            |_, _| {},
        )
        .unwrap();

        let encrypted_bytes = encrypted.into_inner();
        // Verify it's a v14 header
        assert!(encrypted_bytes.starts_with(b"[CCRYPT|14|E|"));

        let mut reader = Cursor::new(encrypted_bytes.as_slice());
        let mut decrypted = Vec::new();
        decrypt_chunked(
            &mut reader,
            &mut decrypted,
            &password,
            BufferMode::Ram,
            Some(&keypair.private),
            None,
            |_, _| {},
        )
        .unwrap();

        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    /// Verify v0.7.0 (v11) chunked files still decrypt under v0.7.1.
    ///
    /// Synthesises a v11-format file by re-framing a v13 encryption: the per-chunk
    /// ciphertexts are reused (they're independent of the HMAC scheme), only the
    /// HMAC tags are regenerated with legacy per-chunk keying and the header is
    /// rewritten with the v11 wire format and legacy header-hash semantics.
    #[test]
    fn test_legacy_v11_backward_compat() {
        use hmac::{Hmac, Mac};

        let data = b"backward compat test: v11 from v0.7.0 must still decrypt";
        let password = random_password();
        let algorithms = vec![Algorithm::Aes256];

        // Encrypt with current code (produces v13).
        let mut input = Cursor::new(data.as_slice());
        let mut encrypted = Cursor::new(Vec::new());
        encrypt_chunked(
            &mut input, &mut encrypted, &password, &algorithms,
            16, data.len() as u64, false, BufferMode::Ram, None, |_, _| {},
        ).unwrap();
        let v13_bytes = encrypted.into_inner();

        // Walk frames, re-HMAC with legacy per-chunk keying, accumulate full hash.
        let nl = v13_bytes.iter().position(|&b| b == b'\n').unwrap();
        let body = &v13_bytes[nl + 1..];
        let mut new_body = Vec::new();
        let mut full_hasher = Sha256::new();
        let mut offset = 0;
        let mut chunk_index: u64 = 0;
        while offset < body.len() {
            let frame_len_bytes: [u8; 8] = body[offset..offset + 8].try_into().unwrap();
            let frame_len = u64::from_le_bytes(frame_len_bytes) as usize;
            let chunk_salt: [u8; 32] =
                body[offset + 8..offset + 8 + SALT_LEN].try_into().unwrap();
            let ct_start = offset + 8 + SALT_LEN + HMAC_LEN;
            let ct_end = offset + 8 + frame_len;
            let ciphertext = &body[ct_start..ct_end];

            let legacy_key = derive_legacy_chunk_hmac_key(&password, &chunk_salt);
            let mut mac = <Hmac<Sha256>>::new_from_slice(legacy_key.as_ref()).unwrap();
            mac.update(&chunk_index.to_le_bytes());
            mac.update(&frame_len_bytes);
            mac.update(&chunk_salt);
            mac.update(ciphertext);
            let new_hmac: [u8; 32] = mac.finalize().into_bytes().into();

            new_body.extend_from_slice(&frame_len_bytes);
            new_body.extend_from_slice(&chunk_salt);
            new_body.extend_from_slice(&new_hmac);
            new_body.extend_from_slice(ciphertext);
            full_hasher.update(&frame_len_bytes);
            full_hasher.update(&chunk_salt);
            full_hasher.update(&new_hmac);
            full_hasher.update(ciphertext);

            chunk_index += 1;
            offset = ct_end;
        }
        let chunk_count = chunk_index;
        let full_hash: [u8; 32] = full_hasher.finalize().into();

        // Build v11 header. Legacy header hash covers algo_codes || argon2_str
        // || chunk_count || full_hash (no salt hashing in v11).
        let argon2_str = "65536,3,4";
        let algo_codes = "A";
        let mut hh = Sha256::new();
        hh.update(algo_codes.as_bytes());
        hh.update(argon2_str.as_bytes());
        hh.update(chunk_count.to_string().as_bytes());
        hh.update(&full_hash);
        let header_hash: [u8; 32] = hh.finalize().into();
        let to_hex = |bytes: &[u8; 32]| {
            let mut s = String::with_capacity(64);
            for &b in bytes {
                s.push_str(&format!("{:02x}", b));
            }
            s
        };
        let header_line = format!(
            "[CCRYPT|11|{}|{}|{}|{}|{}]\n",
            algo_codes,
            argon2_str,
            chunk_count,
            to_hex(&full_hash),
            to_hex(&header_hash),
        );

        let mut v11_bytes = header_line.into_bytes();
        v11_bytes.extend_from_slice(&new_body);

        // Decrypt the synthesised v11 file.
        let mut reader = Cursor::new(v11_bytes.as_slice());
        let mut decrypted = Vec::new();
        decrypt_chunked(
            &mut reader, &mut decrypted, &password,
            BufferMode::Ram, None, None, |_, _| {},
        ).unwrap();

        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_v13_cross_file_splicing_rejected() {
        // K-1 regression: a chunk frame from one v13 file must not be accepted
        // as a valid frame in another v13 file, even when both share password,
        // algorithms, argon2 params, and chunk count. The per-file HMAC key
        // derived from each file's random file_salt makes the HMAC tag on a
        // foreign frame invalid when verified under the destination file's key.

        let password = random_password();
        let algorithms = vec![Algorithm::Aes256];
        let chunk_size = 16;
        // Equal length, chunk_size-aligned → identical chunk count per file.
        let data_a: [u8; 64] = *b"file_A chunk_0: file_A chunk_1: file_A chunk_2: file_A chunk_3: ";
        let data_b: [u8; 64] = *b"file_B chunk_0: file_B chunk_1: file_B chunk_2: file_B chunk_3: ";

        let encrypt = |data: &[u8]| -> Vec<u8> {
            let mut out = Cursor::new(Vec::new());
            encrypt_chunked(
                &mut Cursor::new(data),
                &mut out,
                &password,
                &algorithms,
                chunk_size,
                data.len() as u64,
                false,
                BufferMode::Ram,
                None,
                |_, _| {},
            )
            .unwrap();
            out.into_inner()
        };
        let bytes_a = encrypt(&data_a);
        let bytes_b = encrypt(&data_b);

        // Both must be v13, and their file_salts must differ — the property the
        // fix depends on.
        assert!(bytes_a.starts_with(b"[CCRYPT|13|"));
        assert!(bytes_b.starts_with(b"[CCRYPT|13|"));
        let (header_a, _) = Header::parse(&bytes_a).unwrap();
        let (header_b, _) = Header::parse(&bytes_b).unwrap();
        assert_ne!(header_a.salt, header_b.salt);

        // Split each file into header-line + body; parse body into frames.
        let nl_a = bytes_a.iter().position(|&b| b == b'\n').unwrap();
        let nl_b = bytes_b.iter().position(|&b| b == b'\n').unwrap();
        let body_a = &bytes_a[nl_a + 1..];
        let body_b = &bytes_b[nl_b + 1..];

        let parse_frames = |body: &[u8]| -> Vec<Vec<u8>> {
            let mut frames = Vec::new();
            let mut off = 0;
            while off < body.len() {
                let frame_len_bytes: [u8; 8] = body[off..off + 8].try_into().unwrap();
                let frame_len = u64::from_le_bytes(frame_len_bytes) as usize;
                frames.push(body[off..off + 8 + frame_len].to_vec());
                off += 8 + frame_len;
            }
            frames
        };
        let frames_a = parse_frames(body_a);
        let frames_b = parse_frames(body_b);
        assert_eq!(frames_a.len(), frames_b.len());
        assert!(frames_a.len() >= 2);

        // Splice: keep file A's frame 0, substitute file B's frame 1, keep
        // the rest of file A. Chunk indices stay aligned so the chunk_index
        // binding in the HMAC input isn't what rejects the splice — it's the
        // file_salt-derived HMAC key mismatch.
        let mut spliced_body = Vec::new();
        spliced_body.extend_from_slice(&frames_a[0]);
        spliced_body.extend_from_slice(&frames_b[1]);
        for frame in &frames_a[2..] {
            spliced_body.extend_from_slice(frame);
        }

        // Attacker recomputes the unkeyed checksums to make every non-MAC
        // field self-consistent — this is the realistic attack scenario.
        let mut hasher = Sha256::new();
        hasher.update(&spliced_body);
        let spliced_full_hash: [u8; 32] = hasher.finalize().into();
        let spliced_header = Header::with_chunks(
            header_a.algorithms.clone(),
            header_a.salt,
            header_a.argon2_params,
            header_a.chunk_count.unwrap(),
            spliced_full_hash,
        );
        let mut spliced = spliced_header.serialize().into_bytes();
        spliced.extend_from_slice(&spliced_body);

        // Decrypt must fail at chunk 1's HMAC check, before any plaintext
        // is emitted from the spliced chunk.
        let result = decrypt_chunked(
            &mut Cursor::new(spliced.as_slice()),
            &mut Vec::new(),
            &password,
            BufferMode::Ram,
            None,
            None,
            |_, _| {},
        );
        let err = result.expect_err("spliced v13 file must fail to decrypt");
        let msg = err.to_string();
        assert!(
            msg.contains("Chunk 1") && msg.contains("HMAC"),
            "expected chunk 1 HMAC failure, got: {}",
            msg
        );
    }
}
