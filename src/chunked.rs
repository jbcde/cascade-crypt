use rand::Rng;
use sha2::{Digest, Sha256};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use zeroize::Zeroizing;

use crate::buffer::BufferMode;
use crate::cascade::{decrypt_layers, encrypt_layers, CascadeError};
use crate::crypto::Algorithm;
use crate::header::{Argon2Params, Header, HeaderError};
use crate::hybrid::{HybridPrivateKey, HybridPublicKey};

const SALT_LEN: usize = 32;
const FRAME_PREFIX_LEN: usize = 8; // u64 LE chunk length

/// Check whether a file should be chunked based on available RAM.
/// Returns `Some(chunk_size)` if `file_size > 3/4 * available_ram`, else `None`.
/// Default chunk size = available_ram / 4.
#[cfg(target_os = "linux")]
pub fn should_chunk(file_size: u64) -> Option<usize> {
    let available = crate::buffer::get_available_memory()? as u64;
    let threshold = (available * 3) / 4;
    if file_size > threshold {
        // Chunk size = 1/4 of available RAM, minimum 1 MiB
        let chunk = (available / 4).max(1024 * 1024) as usize;
        Some(chunk)
    } else {
        None
    }
}

#[cfg(not(target_os = "linux"))]
pub fn should_chunk(_file_size: u64) -> Option<usize> {
    None
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
        1
    } else {
        ((file_size as usize) + chunk_size - 1) / chunk_size
    };

    // Write placeholder header — we'll seek back to overwrite with final hash
    let placeholder_header = Header::with_chunks(
        algorithms.to_vec(),
        Argon2Params::default(),
        chunk_count as u64,
        [0u8; 32], // placeholder hash
    );
    let header_str = if let Some(pk) = pubkey {
        placeholder_header.serialize_encrypted(pk)?
    } else {
        placeholder_header.serialize()
    };
    let header_len = header_str.len();
    output
        .write_all(header_str.as_bytes())
        .map_err(CascadeError::Io)?;

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

        // Frame: [8-byte len][32-byte salt][ciphertext]
        let frame_len = (SALT_LEN + ciphertext.len()) as u64;
        let frame_len_bytes = frame_len.to_le_bytes();

        output
            .write_all(&frame_len_bytes)
            .map_err(CascadeError::Io)?;
        output.write_all(&salt).map_err(CascadeError::Io)?;
        output.write_all(&ciphertext).map_err(CascadeError::Io)?;

        hasher.update(&frame_len_bytes);
        hasher.update(&salt);
        hasher.update(&ciphertext);

        progress(i + 1, chunk_count);
    }

    // Compute final hash and rewrite header
    let full_hash: [u8; 32] = hasher.finalize().into();
    let final_header = Header::with_chunks(
        algorithms.to_vec(),
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
    let padded = final_header_str.into_bytes();
    // For v9 plaintext headers, the hash field is always 64 hex chars,
    // so placeholder and final headers are exactly the same size.
    if padded.len() != header_len {
        return Err(CascadeError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Header size mismatch on rewrite — encrypted chunked headers not yet supported",
        )));
    }
    output.write_all(&padded).map_err(CascadeError::Io)?;

    Ok(())
}

/// Decrypt a chunked file from a reader, writing plaintext chunks to the writer.
///
/// Reads frame-by-frame from `input`, keeping memory proportional to one chunk
/// at a time. Hash integrity is verified after all frames are processed.
pub fn decrypt_chunked<R, W, F>(
    input: &mut R,
    output: &mut W,
    password: &[u8],
    buffer_mode: BufferMode,
    private_key: Option<&HybridPrivateKey>,
    mut progress: F,
) -> Result<(), CascadeError>
where
    R: Read,
    W: Write,
    F: FnMut(usize, usize),
{
    // Read header line (everything up to and including '\n')
    let mut reader = BufReader::new(input);
    let mut header_bytes = Vec::with_capacity(4096);
    reader
        .read_until(b'\n', &mut header_bytes)
        .map_err(CascadeError::Io)?;
    if header_bytes.is_empty() || header_bytes.last() != Some(&b'\n') {
        return Err(CascadeError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "EOF before header newline",
        )));
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

    let chunk_count = header
        .chunk_count
        .ok_or(HeaderError::InvalidFormat)? as usize;

    // Single-pass: read, hash, and decrypt each frame
    let mut hasher = Sha256::new();
    for i in 0..chunk_count {
        // Read frame length prefix
        let mut frame_len_bytes = [0u8; FRAME_PREFIX_LEN];
        reader
            .read_exact(&mut frame_len_bytes)
            .map_err(CascadeError::Io)?;
        let frame_len = u64::from_le_bytes(frame_len_bytes) as usize;

        if frame_len < SALT_LEN {
            return Err(CascadeError::Crypto(
                crate::crypto::CryptoError::DecryptionFailed(
                    "Chunk frame too small for salt".into(),
                ),
            ));
        }

        // Read frame data (salt + ciphertext)
        let mut frame_data = vec![0u8; frame_len];
        reader
            .read_exact(&mut frame_data)
            .map_err(CascadeError::Io)?;

        // Hash the frame prefix + frame data
        hasher.update(&frame_len_bytes);
        hasher.update(&frame_data);

        // Extract salt and ciphertext
        let salt: [u8; 32] = frame_data[..SALT_LEN].try_into().unwrap();
        let ciphertext = &frame_data[SALT_LEN..];

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
    if computed_hash != expected_hash {
        return Err(CascadeError::Header(HeaderError::CiphertextHashMismatch));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

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
            |_, _| {},
        );
        assert!(result.is_err());
    }
}
