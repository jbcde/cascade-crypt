# Changelog

All notable changes to cascrypt will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
