# Changelog

All notable changes to cascrypt will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.7.2] - 2026-04-15

### Security
- **Fixed:** Closed RUSTSEC-2026-0097 (`rand 0.8.5` unsoundness advisory) by migrating to `rand 0.9`. The specific unsound pattern flagged by the advisory (`rand::rng()` with a custom logger) was not reachable from cascrypt's usage — cascrypt on `rand 0.8` never called `rand::rng()` (that function is 0.9-only) — but the crate-level version match kept the advisory flagged. Bumping to `rand 0.9` removes the flag and brings cascrypt onto the current supported RNG API.
- Refreshed dependency lockfile: transitive minor/patch bumps for `bitflags`, `cc`, `fastrand`, `hashbrown`, `hybrid-array`, `indexmap`, `libc`, `rand_core`, `rayon`, `rtoolbox`, `semver`, `zerocopy`, and `zerocopy-derive`. Fuzz workspace `Cargo.lock` refreshed in parallel.

### Changed
- `rand` dependency: `"0.8"` → `"0.9"`. API migration across 7 files:
  - `rand::thread_rng()` → `rand::rng()`
  - `Rng::gen()` → `Rng::random()` (avoids collision with the `gen` keyword reserved in Rust 2024)
  - `rand::seq::SliceRandom` (for `.choose()`) → `rand::seq::IndexedRandom` (trait split in 0.9)
- `x25519-dalek`: enabled `getrandom` feature so `StaticSecret::random()` and `EphemeralSecret::random()` are available without requiring `rand_core 0.6` trait bridging. Replaces `random_from_rng(rand::thread_rng())` at `hybrid.rs:86` and `hybrid.rs:126` — same cryptographic behavior, different plumbing.

### Known issues
- `crypto-common 0.2.0` remains pinned (yanked from crates.io). Upstream `0.2.1` removed `BlockSizes`, `Block`, and `ParBlocksSizeUser` types that `cipher 0.5.0-rc.6` depends on — updating `crypto-common` would require unpinning the cipher 0.5 pre-release crates, which cannot be done without breaking the six cipher algorithms that ride on that ecosystem. Status is unchanged from v0.7.1.

### Compatibility
- **No wire format changes.** v0.7.1 files decrypt under v0.7.2 without modification; v0.7.2 files decrypt under v0.7.1 without modification.
- No changes to the public library API — the `rand` migration is internal. Callers using `cascrypt` as a library see identical function signatures and identical cryptographic properties (same ciphers, same key derivation, same integrity constructions). Only the RNG backend supplying randomness to nonces, IVs, and salts was swapped, which is invisible on the wire.

## [0.7.1] - 2026-04-14

### Security
- **Fixed:** Cross-file chunk splicing in chunked encryption (v11/v12). The per-chunk HMAC key was derived from `HKDF(password, chunk_salt)` with the chunk salt traveling inside each frame, so a frame from file A was a valid frame in any other file that shared the same password and algorithm cascade. An attacker with access to two such ciphertexts could transplant chunks between them — producing a file where every integrity check (per-chunk HMAC, full-file hash, header hash) passed, but which decrypted to a recombination of plaintext from the source files. Found by adversarial review (`kelly-review.md`, finding K-1) and verified by constructed exploit.
- **Fix:** The HMAC key is now derived per-file from `HKDF(password, file_salt)` where `file_salt` is a fresh 32-byte random value stored in the header. In v13 (plaintext chunked) the salt is a new header field covered by the header hash. In v14 (encrypted chunked) the salt lives in the ChaCha20-Poly1305-authenticated `EncryptedPayload`. The key is derived once per file and reused for every chunk, so the per-chunk HKDF call is also removed — net simpler and net safer.
- HKDF domain separator changed from `"cascrypt-chunk-hmac"` to `"cascrypt-file-hmac"` to reflect the new binding.
- The per-chunk `chunk_salt` is retained — it still drives Argon2id cascade key derivation for each chunk's independent cipher stack. Only the HMAC keying changed.

### Added
- Header versions **v13** (plaintext chunked) and **v14** (encrypted chunked) — emitted by all chunked encryption in v0.7.1+.
- `legacy_chunk_hmac` internal flag on `Header` so the decryption path can route v11/v12 files through the legacy per-chunk HMAC derivation.
- Backward-compatible decryption of v11/v12 files (from v0.7.0): `decrypt_chunked` detects the legacy version, uses the old `HKDF(password, chunk_salt)` HMAC keying, and validates as before. Legacy files remain vulnerable to the splicing attack described above — re-encrypt with v0.7.1 to gain the new protection.
- Test `test_legacy_v11_backward_compat` synthesises a v11-format chunked file and verifies it decrypts under v0.7.1.

### Changed
- `Header::with_chunks()` now takes `salt` as a required parameter (was generated internally). Callers must pass the same file salt to both the placeholder and the final header rewrite.
- `Header::compute_hash_bytes()` hashes `self.salt` except when `legacy_chunk_hmac` is set (preserving the v11/v12 hash recipe for backward-compat verification).
- `header.salt` parsed from v13 headers is the real file salt (in v11 the field was a discarded placeholder).
- `Header::is_chunked()` now returns true for versions 11, 12, 13, and 14; `Header::is_encrypted()` now recognises 8, 12, and 14.

### Compatibility
- **v0.7.0 chunked files (v11/v12) continue to decrypt** under v0.7.1 — no re-encryption required to read your archive.
- **New encryptions emit v13/v14.** v0.7.0 and earlier cannot decrypt files produced by v0.7.1+ (forward-only compatibility).
- The v0.6.1 encoder change (8-byte length prefix) remains in effect — files from v0.6.0 or earlier must be decrypted with the prior version first.
- Non-chunked files (v7/v8 headers) are unaffected by this release.

## [0.7.0] - 2026-03-27

### Added
- **Chunked encryption** for files that exceed available memory. Files are split into fixed-size pieces, each encrypted independently through the full algorithm cascade with its own Argon2id-derived key from a unique random salt. A SHA-256 hash over all chunk frames is verified on decryption.
- Chunked mode activates automatically when file size exceeds 3/4 of available RAM
- `--chunk <SIZE>` flag for manual chunk size control — accepts human-readable sizes (`512k`, `100m`, `4g`, case-insensitive). Use this when the recipient has less RAM than the encrypting machine, ensuring they can decrypt without memory pressure.
- Header versions 11 (chunked, plaintext) and 12 (chunked, encrypted) with chunk count and frame integrity hash
- Decryption auto-detects chunked files from the header — no flags needed on the receiving end
- Clear error message when attempting to decrypt chunked files from stdin
- 5 new E2E tests covering chunked roundtrip, single-chunk, tamper detection, multi-algorithm cascade, and wrong password

### Changed
- **Cross-platform memory detection:** `get_available_memory()` now works on Linux (`/proc/meminfo`), macOS (`sysctl HW_MEMSIZE`), and Windows (`GlobalMemoryStatusEx`). Auto-chunking previously only worked on Linux.
- `encrypt_layers`, `decrypt_layers`, `derive_keys_parallel` visibility widened to `pub(crate)` (no public API change)
- `buffer::get_available_memory()` visibility widened to `pub(crate)`

### Security
- **Per-chunk HMAC-SHA256** authentication: each chunk frame carries an HMAC tag verified before decryption, preventing plaintext emission for tampered chunks. HMAC key derived via HKDF-SHA256 from password + chunk salt. HMAC binds chunk index, frame length, salt, and ciphertext — prevents tampering, reordering, and length manipulation. Full-file SHA-256 hash retained for truncation detection.
- Chunked hash verification uses constant-time comparison (`subtle::ConstantTimeEq`) to prevent timing side channels
- Bounded header read in chunked decryption (64 KiB cap) prevents DoS from missing newline
- Frame length capped at the lesser of available memory and 8 GiB to prevent OOM from crafted inputs
- Chunk count validated against `MAX_CHUNK_COUNT` to prevent DoS from attacker-controlled headers
- Chunk count arithmetic uses checked conversion (`usize::try_from`) instead of `as` cast
- Output file deleted on hash verification failure to avoid leaving unverified plaintext on disk
- Unused salt field in chunked headers zeroed instead of filled with misleading random bytes

### Fixed
- stderr flush in progress callback so chunk counter updates in real time
- v10 encrypted chunked header serialization and `--pubkey` documentation

### Breaking Changes
- **Chunked frame format changed:** Per-chunk HMAC authentication added to the frame wire format (`[frame_len][salt][hmac][ciphertext]`). Header versions bumped from v9/v10 to v11/v12. Files encrypted with the previous v0.7.0-unstable chunked format cannot be decrypted. Non-chunked files (v7/v8 headers) are unaffected.

### Build
- `Cargo.lock` now committed (was gitignored) — guarantees reproducible builds on fresh clones
- Added explicit `cipher05` pin (`cipher = "=0.5.0-rc.6"`) in `Cargo.toml` as safety net against `cargo update` resolving to incompatible `cipher 0.5.0` stable

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
