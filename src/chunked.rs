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
/// Maximum chunk count to prevent DoS from attacker-controlled headers.
const MAX_CHUNK_COUNT: u64 = u32::MAX as u64;

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
    let file_salt: [u8; 32] = rand::thread_rng().gen();
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

        let salt: [u8; 32] = rand::thread_rng().gen();
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
    let hmac_key = derive_file_hmac_key(password, &header.salt);

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

        // Verify HMAC BEFORE decrypting — reject tampered chunks without emitting plaintext
        let expected_hmac = compute_chunk_hmac(&hmac_key, i as u64, &frame_len_bytes, &salt, ciphertext);
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
        let bytes: [u8; 16] = rand::thread_rng().gen();
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
        // Verify it's a v10 header
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
}
