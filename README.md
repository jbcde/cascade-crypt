# cascrypt

Cascading binary encryption tool with user-controlled algorithm ordering. Encrypt files through multiple layers of encryption, applied in the order you specify.

> **v0.7.0 Breaking Changes:** Chunked encryption now uses per-chunk HMAC-SHA256 authentication (header versions v11/v12). Files encrypted with v0.7.0-unstable chunked format (v9/v10) must be re-encrypted. Non-chunked files (v7/v8) are unaffected. The v0.6.1 encoder change (8-byte length prefix) also remains — files from v0.6.0 or earlier must be decrypted with the prior version first. See [CHANGELOG.md](CHANGELOG.md) for details.

## Features

- **20 symmetric ciphers** - mix and match in any order
- **Cascading encryption** - algorithms applied sequentially in command-line order
- **Chunked mode** - encrypt files of any size without exceeding available memory, with per-chunk HMAC authentication
- **Combined flags** - use `-ASC` instead of `-A -S -C` for convenience
- **Random mode** - randomly select N algorithms (with duplicates) for unpredictable layering
- **Silent mode** - suppress all output for operational security
- **Auto-decryption** - header stores algorithm order, decryption reverses automatically
- **Argon2id key derivation** - unique keys derived per algorithm layer
- **SHA-256 integrity** - header hash detects tampering
- **Header encryption** - `--pubkey` activates X25519 + ML-KEM-1024 post-quantum encryption to hide algorithm order

## Installation

```bash
cargo build --release
# Binary at ./target/release/cascrypt
```

## Usage

### Encrypt (manual algorithm selection)
```bash
cascrypt -ASC -i secret.bin -o secret.enc
```
Encrypts with AES-256 → Serpent → ChaCha20 (in that order). Flags can be combined (`-ASC`) or separate (`-A -S -C`). You will be prompted for a password interactively.

### Encrypt (random algorithm selection)
```bash
cascrypt -n 20 -i secret.bin -o secret.enc
```
Encrypts with 20 randomly selected algorithms (duplicates allowed).

### Decrypt
```bash
cascrypt -d -i secret.enc -o secret.bin
```
Algorithm order is read from the file header automatically. Password is prompted interactively.

### Silent mode
```bash
cascrypt -s -n 50 -i secret.bin -o secret.enc
```
Suppresses all status output (algorithm chain, completion messages).

### Options
```
-d, --decrypt       Decrypt mode
-n, --random N      Use N randomly selected algorithms (disables manual flags)
-s, --silent        Suppress all status output
    --progress      Show progress during encryption/decryption
    --chunk SIZE    Force chunked encryption (e.g. 512k, 100m, 4g)
-i, --input FILE    Input file (use '-' for stdin)
-o, --output FILE   Output file (use '-' for stdout)
    --keyfile FILE  Read key from file
    --pubkey FILE   Recipient's public key for header protection (encrypt)
    --privkey FILE  Private key for protected headers (decrypt)
```

## Algorithms

| Flag | Code | Algorithm | Block/Stream | Block Size |
|------|------|-----------|--------------|------------|
| `-T` | T | 3DES-CBC | Block | **64-bit** ⚠ |
| `-A` | A | AES-256-GCM | Block (AEAD) | 128-bit |
| `-R` | R | ARIA-256-CBC | Block | 128-bit |
| `-N` | N | Ascon-128 | Block (AEAD) | 128-bit |
| `-B` | B | Blowfish-256-CBC | Block | **64-bit** ⚠ |
| `-M` | M | Camellia-256-CBC | Block | 128-bit |
| `-F` | F | CAST5-CBC | Block | **64-bit** ⚠ |
| `-C` | C | ChaCha20-Poly1305 | Stream (AEAD) | — |
| `-J` | J | GIFT-128-CBC | Block | 128-bit |
| `-I` | I | IDEA-CBC | Block | **64-bit** ⚠ |
| `-K` | K | Kuznyechik-CBC | Block | 128-bit |
| `-G` | G | Magma-CBC (GOST) | Block | **64-bit** ⚠ |
| `-6` | 6 | RC6-CBC | Block | 128-bit |
| `-E` | E | SEED-CBC | Block | 128-bit |
| `-S` | S | Serpent-256-CBC | Block | 128-bit |
| `-4` | 4 | SM4-CBC | Block | 128-bit |
| `-P` | P | Speck128/256-CBC | Block | 128-bit |
| `-3` | 3 | Threefish-256-CBC | Block | 256-bit |
| `-W` | W | Twofish-256-CBC | Block | 128-bit |
| `-X` | X | XChaCha20-Poly1305 | Stream (AEAD) | — |

**⚠ 64-bit block ciphers** (3DES, Blowfish, CAST5, IDEA, Magma) are vulnerable to birthday attacks when encrypting large amounts of data. Collisions become likely after ~32GB with the same key. Avoid these for large files or use them only as inner layers in a cascade.

## Chunked Encryption

By default, cascrypt loads the entire file into memory for encryption. When the file size exceeds 3/4 of available RAM, chunked mode activates automatically — the file is split into fixed-size pieces, each encrypted independently through the full algorithm cascade, then written sequentially to the output.

Decryption detects chunked files from the header and processes them one chunk at a time. No special flags are needed on the receiving end.

### Manual chunking with `--chunk`

Auto-detection only considers the machine doing the encryption. If the recipient has less RAM than you do, the encrypted file may still be too large for them to decrypt in one pass. Use `--chunk` to set an explicit chunk size:

```bash
# 10 GiB file, recipient has 8 GiB RAM — chunk to 1 GiB
cascrypt -AC --chunk 1g -i large.bin -o large.enc
```

The recipient decrypts normally:
```bash
cascrypt -d -i large.enc -o large.bin
```

Each chunk is decrypted independently, so peak memory stays proportional to the chunk size regardless of total file size.

Size suffixes: `k` (kilobytes), `m` (megabytes), `g` (gigabytes). Case-insensitive, no space between number and unit.

### Security properties

- Each chunk derives its own key material from a unique random 32-byte salt via Argon2id
- **Per-chunk HMAC-SHA256** authentication — each chunk frame carries an HMAC tag that is verified *before* decryption, so tampered chunks never produce plaintext output. The HMAC binds the chunk index, frame length, salt, and ciphertext, preventing tampering, reordering, and length manipulation.
- A SHA-256 hash over all chunk frames is stored in the header and verified after decryption to detect truncation
- Frame size is capped at available memory to prevent OOM from crafted inputs

### Limitations

- `--lock` (puzzle lock) is not compatible with chunked encryption
- Chunked encryption requires file I/O (not stdin/stdout) since the header is finalized after all chunks are written

## Header Encryption (`--pubkey`)

Without `--pubkey`, the file header is plaintext. Anyone can see which algorithms were used, the Argon2 parameters, and the chunk count. Your data is still protected by the password — the header just isn't secret.

Passing `--pubkey` encrypts the header using hybrid post-quantum asymmetric encryption (X25519 + ML-KEM-1024). This is the only way to activate the post-quantum cryptography in cascrypt. Without it, there is no asymmetric encryption involved at all.

### Why encrypt the header?

With a plaintext header, an attacker knows they need to break AES → Serpent → ChaCha20. With an encrypted header, they don't even know which of the 6+ billion possible algorithm combinations to attack.

### Key Generation

Generate a hybrid keypair (X25519 + ML-KEM-1024):

```bash
# Generate keypair and export public key
cascrypt keygen -o my.keypair --export-pubkey my.pubkey

# Or export public key later
cascrypt export-pubkey -i my.keypair -o my.pubkey
```

The keypair combines:
- **X25519**: Classical elliptic curve Diffie-Hellman (256-bit security)
- **ML-KEM-1024**: Post-quantum lattice-based KEM (NIST FIPS 203, quantum-resistant)

### Protected Encryption

Encrypt with a protected header using the recipient's public key:

```bash
cascrypt -ASC -i secret.bin -o secret.enc --pubkey recipient.pubkey
```

The algorithm order and salt are now encrypted. An attacker sees only:
```
[CCRYPT|8|E|<encrypted_keys>|<encrypted_metadata>|<ciphertext_hash>|<header_hash>]
```

### Protected Decryption

Decrypt using your private key (full keypair file):

```bash
cascrypt -d -i secret.enc -o secret.bin --privkey my.keypair
```

Without the private key, decryption fails:
```
Error: Encrypted header requires private key
```

## File Format

### Version 7 (Plaintext Header)
```
[CCRYPT|7|ASCX|<salt_hex>|<argon2_params>|<ciphertext_hash>|<header_hash>]
<encrypted payload>
```

- **Version**: 7
- **Algorithm codes**: Letters indicating encryption order (visible)
- **Salt**: 32-byte random salt (hex encoded)
- **SHA-256**: Hash of algorithm codes + salt

### Version 8 (Encrypted Header)
```
[CCRYPT|8|E|<encapsulated_keys_b64>|<encrypted_payload_b64>|<ciphertext_hash>|<header_hash>]
<encrypted payload>
```

- **Version**: 8
- **E**: Marker for encrypted header
- **Encapsulated keys**: X25519 ephemeral public key + ML-KEM ciphertext (base64)
- **Encrypted payload**: Algorithm codes + salt encrypted with ChaCha20-Poly1305 (base64)
- **SHA-256**: Hash of encrypted components

### Version 11 (Chunked, Plaintext Header)
```
[CCRYPT|11|<algo_codes>|<argon2_params>|<chunk_count>|<full_hash>|<header_hash>]
<chunk_frame_0><chunk_frame_1>...
```

- **Version**: 11
- **Chunk count**: Number of chunk frames following the header
- **Full hash**: SHA-256 of all concatenated chunk frames (detects truncation)
- Each chunk frame: `[8-byte LE length][32-byte salt][32-byte HMAC][ciphertext]`
- HMAC key derived via HKDF-SHA256 from password + chunk salt
- HMAC binds chunk index, frame length, salt, and ciphertext

### Version 12 (Chunked, Encrypted Header)

Same as v8 with `chunk_count` added to the encrypted payload. Chunk frames follow the header in the same format as v11.

## Examples

```bash
# Maximum paranoia - all 20 ciphers
cascrypt -ATWSCXMBFIR4KE36GPJN -i file.bin -o fortress.enc

# Quick and modern
cascrypt -CA -i file.bin -o file.enc

# Random 100-layer encryption with progress
cascrypt --progress -n 100 -i file.bin -o file.enc

# Silent random encryption with protected header (maximum OPSEC)
cascrypt -s -n 50 --pubkey recipient.pubkey -i secret.bin -o secret.enc

# Pipe from stdin
cat secret.txt | cascrypt -AS -i - -o - --keyfile secret.key > encrypted.bin

# Protected header workflow
cascrypt keygen -o alice.keypair --export-pubkey alice.pubkey
cascrypt -ACS -i secret.bin -o secret.enc --pubkey alice.pubkey
cascrypt -d -i secret.enc -o secret.bin --privkey alice.keypair

# Large file with explicit chunk size for low-memory recipients
cascrypt -AC --chunk 1g -i database.bak -o database.enc

# Silent decryption
cascrypt -s -d -i secret.enc -o secret.bin
```

## Security Notes

- **20! = 2,432,902,008,176,640,000** possible algorithm orderings
- **Argon2id** derives unique 256-bit keys per algorithm from master password
- **Random salt** ensures identical files encrypt differently
- **AEAD ciphers** (AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305, Ascon) provide authentication
- **Per-chunk HMAC** in chunked mode verifies integrity before decryption — tampered chunks never produce plaintext
- **Hybrid encryption** combines classical and post-quantum security for header protection
- **Cross-platform** auto-chunking works on Linux, macOS, and Windows
- **Quantum resistance**: Grover's algorithm halves effective key strength. 256-bit ciphers remain secure (128-bit post-quantum). Avoid using *only* 128-bit ciphers (`-F -I -4 -E -6 -J -N`) if quantum resistance matters—include at least one 256-bit cipher in your cascade.

## Limitations

- **Non-chunked mode memory usage: ~2-3x file size** — Multi-layer encryption requires the input plus intermediate buffers. `--buffer=disk` offloads intermediate layers to temp files, but the initial read and final write remain in RAM.
- **Chunked mode** avoids this — memory stays proportional to chunk size. Activates automatically for large files or manually with `--chunk`.

## Performance

Tested on 1MB file through all 20 ciphers (Intel Xeon E-2176M @ 2.70GHz):
- Encryption: ~1.8s
- Decryption: ~1.9s

Bottlenecks: Argon2id key derivation (20 unique keys) and Serpent cipher.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and security updates.

## License

MIT
