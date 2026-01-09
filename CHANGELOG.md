# Changelog

All notable changes to cascrypt will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.1] - 2026-01-09

### Added
- Ciphertext integrity verification via SHA-256 hash in header
- `Header::with_ciphertext()` constructor for creating headers with ciphertext hash
- `Header::verify_ciphertext()` method to verify ciphertext integrity before decryption
- `CiphertextHashMismatch` error for tampered/corrupted ciphertext detection
- Unit tests for ciphertext tampering detection
- Unit test for duplicate algorithm layers

### Changed
- Header format version bumped: plaintext v1→v3, encrypted v2→v4
- Header now includes 32-byte SHA-256 hash of ciphertext
- Encryption flow: ciphertext is now generated before header serialization
- Decryption flow: ciphertext hash is verified before attempting decryption
- Key derivation now includes layer index in salt (unique key per layer position)
- `derive_keys_parallel` returns `Vec` instead of `HashMap` (one key per layer, not per algorithm)

### Security
- **Fixed:** Header hash now covers ciphertext, preventing payload substitution attacks on CBC-mode ciphers
- **Fixed:** Each layer now derives a unique key even when the same algorithm is used multiple times in a cascade
