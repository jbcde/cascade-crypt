# Changelog

All notable changes to cascrypt will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.7.0-unstable] - 2026-02-09

### Added
- **Chunked encryption** for files that exceed available memory. Files are split into fixed-size pieces, each encrypted independently through the full algorithm cascade with its own Argon2id-derived key from a unique random salt. A SHA-256 hash over all chunk frames is verified on decryption.
- Chunked mode activates automatically when file size exceeds 3/4 of available RAM
- `--chunk <SIZE>` flag for manual chunk size control — accepts human-readable sizes (`512k`, `100m`, `4g`, case-insensitive). Use this when the recipient has less RAM than the encrypting machine, ensuring they can decrypt without memory pressure.
- Header versions 9 (chunked, plaintext) and 10 (chunked, encrypted) with chunk count and frame integrity hash
- Decryption auto-detects chunked files from the header — no flags needed on the receiving end
- 5 new E2E tests covering chunked roundtrip, single-chunk, tamper detection, multi-algorithm cascade, and wrong password

### Changed
- `encrypt_layers`, `decrypt_layers`, `derive_keys_parallel` visibility widened to `pub(crate)` (no public API change)
- `buffer::get_available_memory()` visibility widened to `pub(crate)`

## [0.6.1] - 2026-02-09

### Changed
- Encoder length prefix widened from 4 bytes (`u32`) to 8 bytes (`u64`), removing the 4 GiB file size limit
- `encoder::encode()` now returns `String` directly (was `Result<String, &'static str>`) — no size limit to enforce
- Removed `CascadeError::InputTooLarge` variant (no longer reachable)

### Breaking Changes
- **Backward compatibility:** Files encrypted with v0.6.0 or earlier use a 4-byte length prefix in the encoder and cannot be decoded by v0.6.1. Decrypt with the prior version before upgrading, then re-encrypt.

## [0.6.0] - 2026-02-08

### Security
- **Fixed:** Public decrypt API (`decrypt`, `decrypt_with_progress`, `decrypt_with_buffer_mode`, `decrypt_protected`, `decrypt_protected_with_progress`, `decrypt_protected_with_buffer_mode`) now returns `Zeroizing<Vec<u8>>` — plaintext was previously held in unprotected heap memory between decryption and caller consumption
- **Fixed:** `encoder::decode()` internal base64-decoded buffer now wrapped in `Zeroizing` — plaintext was previously left unzeroized in freed heap memory

### Changed
- Removed legacy encoder fallback that accepted raw base64 without length prefix — all files since v0.4.1 use the length-prefixed format, and the v0.4.0 header break makes pre-v0.4.1 files unreachable
- `encoder::decode()` now returns `Result<Zeroizing<Vec<u8>>, DecodeError>` with a typed `DecodeError` enum (was `Result<Vec<u8>, String>`)
- Encrypt results in CLI handler wrapped in `Zeroizing` for uniform type handling with decrypt results

### Breaking Changes
- **Backward compatibility:** Files encrypted with pre-v0.4.1 encoders (raw base64 without length prefix) can no longer be decoded. This is a theoretical break only — the v0.4.0 header format change already made such files unreadable. Files from v0.4.0 onward are fully compatible.

## [0.5.2] - 2026-02-06

### Security
- **Fixed:** Keypair and public key files (`keygen`, `export-pubkey`) now written with mode 0600 on Unix — previously inherited umask (typically 0644), making private key material world-readable
- **Fixed:** Argon2 parameters parsed from headers are now bounds-checked (m_cost <= 4 GiB, t_cost <= 100, p_cost <= 255, all > 0) — prevents denial-of-service from crafted headers with extreme values

### Changed
- Added documentation on `BufferMode::Disk` and `LayerBuffer` clarifying that disk mode bounds peak memory to ~2x data size per layer, not constant memory
- Added explanatory comment on `cipher05_cbc_impl!` macro documenting why cipher 0.5 traits are imported through `magma`'s re-export (dual cipher 0.4/0.5 coexistence constraint)

## [0.5.1] - 2026-02-06

### Security
- **Fixed:** Password string in `get_password()` now wrapped in `Zeroizing` immediately, ensuring zeroization on error paths (e.g. password mismatch)
- **Fixed:** `Header::parse()` panic on malformed input with missing fields (e.g. `[CCRYPT]\n`) — now returns `InvalidMagic` error

### Changed
- Unified algorithm parsing into a single pass (was two independent code paths that could silently diverge)
- Removed all `MaybeUninit`/`unsafe` usage for random byte generation — replaced with zero-initialized arrays
- Pre-release cipher crate versions pinned with exact (`=`) versions to prevent incompatible upgrades
- Added explanatory comment in `Cargo.toml` about cipher 0.5 ecosystem constraints

### Added
- Fuzz targets for `Header::parse`, `Header::parse_encrypted`, `encoder::decode`, and `crypto::decrypt` (requires nightly: `cargo +nightly fuzz run <target>`)
- Limitations section in README documenting 4 GiB file size cap and memory requirements

## [0.5.0] - 2026-02-05

### Security
- **Fixed:** CBC padding validation now fully constant-time (prevents padding oracle timing attacks)
- **Fixed:** Password confirmation string now zeroized after use (was lingering in heap memory)
- **Fixed:** Derived encryption keys now use `LockedVec` with automatic `munlock` on drop (previously `mlock`'d memory was never unlocked)
- **Fixed:** Disk-mode buffer now securely wipes stale data from inactive temp file after each layer
- **Fixed:** `LayerBuffer::finalize()` now returns `Zeroizing<Vec<u8>>` to prevent un-zeroized plaintext copies
- **Fixed:** `encoder::encode()` now returns `Result` with explicit bounds check, preventing silent u32 truncation on files >4 GiB

### Changed
- Removed `clap` and `indicatif` dependencies — hand-rolled CLI parser and simple stderr progress
- Binary size reduced from 1.4 MB to 1.1 MB (stripped), or 580 KB with UPX compression
- Public encrypt API now takes `&[Algorithm]` instead of `Vec<Algorithm>` (avoids unnecessary allocation)
- Removed dead `Header::compute_hash()` method

## [0.4.2] - 2026-02-03

### Added
- Copy-on-write filesystem detection: warns when temp directory is on btrfs, ZFS, bcachefs, or NILFS2 (secure deletion not guaranteed on CoW filesystems)
- Documented puzzle lock feature in README and USAGE (clarified it is not encryption)
- Block size column in algorithm tables showing 64-bit vs 128-bit block sizes

### Fixed
- `SecureTempFile` Drop impl now calls `fsync()` before unlinking to ensure overwrites hit disk

### Documentation
- Algorithm tables in README and USAGE now sorted alphabetically
- 64-bit block ciphers (3DES, Blowfish, CAST5, IDEA, Magma) clearly marked with warning in tables
- Added explanation of birthday attack vulnerability for 64-bit block ciphers

## [0.4.1] - 2026-02-02

### Changed
- Removed `-k`/`--key` CLI argument (passwords were visible in process list, shell history)
- Password now only accepted via `--keyfile` or interactive prompt (no echo)
- Argon2 parameters strengthened for new files: 64 MiB memory, 3 iterations, 4 parallel lanes (was 19 MiB/2/1)
- Small files now padded to 1KB minimum before encryption (hides exact size)

### CLI Breaking Changes
- Scripts using `-k`/`--key` must switch to `--keyfile` or interactive input
- File format is fully backward compatible - old encrypted files decrypt without issue

### Added
- Warning when using 64-bit block ciphers (3DES, Blowfish, CAST5, IDEA, Magma) - vulnerable to birthday attacks on large files
- Memory locking (`mlock`) for derived keys to prevent swapping to disk
- Backward-compatible padding format (old encrypted files still decrypt correctly)

### Security
- **Fixed:** CLI password exposure via `ps`, `/proc`, shell history - now requires keyfile or interactive input
- **Fixed:** Weak Argon2 defaults - increased to OWASP 2024 recommendations
- **Fixed:** Timing side-channel in header hash verification - now uses constant-time comparison
- **Fixed:** Small file size leakage - minimum 1KB padding hides tiny files

## [0.4.0] - 2026-01-24

### Changed
- **BREAKING:** Header integrity hash now uses full 256-bit SHA-256 (was truncated to 128-bit)
- Header format version bumped: plaintext v5→v7, encrypted v6→v8
- Argon2 parameters now use named constants for clarity

### Breaking Changes
- **Files created with v0.3.x cannot be decrypted with v0.4.0** due to header hash length change. Decrypt with v0.3.x before upgrading, then re-encrypt.

### Security
- Full 256-bit header hash provides 2^128 collision resistance (birthday bound), up from 2^64

## [0.3.1] - 2026-01-24

### Changed
- Wrong password now returns "Decryption failed - wrong password or corrupted data" instead of misleading "Invalid UTF-8"
- Memory pressure during encryption/decryption now fails with IO error instead of silently continuing (risking OOM)
- Thread pool initialization failures now emit a warning instead of being silently ignored

### Added
- Warning when outer encryption layer is not AEAD (recommends ending with `-A`, `-C`, `-X`, or `-N` for authentication)

### Fixed
- `SecureTempFile::secure_delete()` now properly cleans up if `sync_all()` fails

## [0.3.0] - 2026-01-24

### Changed
- **BREAKING:** Migrated post-quantum KEM from Kyber1024 to ML-KEM-1024 (NIST FIPS 203)
- Updated `indicatif` to 0.18 (fixes unmaintained `number_prefix` dependency)

### Breaking Changes
- **Protected headers created with v0.2.x cannot be decrypted with v0.3.0.** Files encrypted with `--pubkey` using Kyber1024 are incompatible with the new ML-KEM-1024 implementation. Files with plaintext headers (no `--pubkey`) are unaffected.
- If you have files with protected headers, decrypt them with v0.2.x before upgrading, then re-encrypt with v0.3.0.

### Security
- Resolved `cargo audit` warnings for unmaintained dependencies (`pqcrypto-kyber`, `number_prefix`)

## [0.2.2] - 2026-01-24

### Changed
- `Header::new()` is now deprecated; use `Header::with_ciphertext()` instead
- `Header::verify_ciphertext()` now returns `MissingCiphertextHash` error if header lacks integrity hash

### Security
- **Fixed:** CLI password argument (`-k`) is now explicitly zeroized after use. Previously, the password string remained in heap memory until the allocator reused that space, potentially exposing it to memory dumps.
- **Fixed:** Library API no longer allows silent bypass of integrity verification. `Header::new()` is deprecated, and `verify_ciphertext()` fails explicitly if no hash is present.
- **Fixed:** Truncated/malformed ciphertext now returns an error instead of panicking. Affected ciphers: Threefish, RC6, Magma, Speck, GIFT (all using manual CBC implementation).

## [0.2.1] - 2026-01-09

### Added
- Ciphertext integrity verification via SHA-256 hash in header
- `Header::with_ciphertext()` constructor for creating headers with ciphertext hash
- `Header::verify_ciphertext()` method to verify ciphertext integrity before decryption
- `CiphertextHashMismatch` error for tampered/corrupted ciphertext detection
- `Argon2Params` struct storing m_cost, t_cost, p_cost in header for forward compatibility
- Unit tests for ciphertext tampering detection
- Unit test for duplicate algorithm layers

### Changed
- Header format version bumped: plaintext v1→v5, encrypted v2→v6
- Header now includes 32-byte SHA-256 hash of ciphertext
- Header now includes Argon2 parameters (memory, time, parallelism)
- Encryption flow: ciphertext is now generated before header serialization
- Decryption flow: ciphertext hash is verified before attempting decryption
- Key derivation now includes layer index in salt (unique key per layer position)
- Key derivation uses Argon2 params from header during decryption (forward compatibility)
- `derive_keys_parallel` returns `Vec` instead of `HashMap` (one key per layer, not per algorithm)

### Security
- **Fixed:** Header hash now covers ciphertext, preventing payload substitution attacks on CBC-mode ciphers
- **Fixed:** Each layer now derives a unique key even when the same algorithm is used multiple times in a cascade
- **Fixed:** Argon2 parameters stored in header ensure files can be decrypted even if defaults change in future versions
