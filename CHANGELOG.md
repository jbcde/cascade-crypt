# Changelog

All notable changes to cascrypt will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
