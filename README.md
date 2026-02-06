# cascrypt

Cascading binary encryption tool with user-controlled algorithm ordering. Encrypt files through multiple layers of encryption, applied in the order you specify.

> **v0.5.0 Breaking Changes:** The `-k`/`--key` command-line password flag has been removed for security reasons (passwords were visible in `ps`, `/proc`, and shell history). Use `--keyfile` or the interactive prompt instead. The animated progress bar has also been replaced with a simple progress counter for bloat reasons. See [CHANGELOG.md](CHANGELOG.md) for details.

## Features

- **20 symmetric ciphers** - mix and match in any order
- **Cascading encryption** - algorithms applied sequentially in command-line order
- **Combined flags** - use `-ASC` instead of `-A -S -C` for convenience
- **Random mode** - randomly select N algorithms (with duplicates) for unpredictable layering
- **Silent mode** - suppress all output for operational security
- **Progress indicator** - optional progress display for long operations (`--progress`)
- **Auto-decryption** - header stores algorithm order, decryption reverses automatically
- **Argon2id key derivation** - unique keys derived per algorithm layer
- **SHA-256 integrity** - header hash detects tampering
- **Hybrid header protection** - optional X25519 + ML-KEM-1024 encryption hides algorithm order

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

## Hybrid Header Protection

By default, the header exposes which algorithms were used (though not the password or keys). For maximum security, you can encrypt the header itself using hybrid asymmetric encryption.

### Why?

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

### Puzzle Lock

The `--lock` flag engages an optional puzzle lock on the encrypted output:

```bash
cascrypt -ASC --pubkey recipient.pubkey --lock -i secret.bin -o secret.enc
```

**Important:** The puzzle lock is **not encryption**. It provides no cryptographic security whatsoever. It is a puzzle—nothing more. The actual security comes entirely from the cipher cascade and the protected header.

The puzzle lock:
- Requires `--pubkey` (only available with protected headers)
- Is **not encryption**—do not rely on it for security
- Applies a reversible transformation to the output
- Cannot be reversed without the matching private key
- Is a puzzle for the curious

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

# Silent decryption
cascrypt -s -d -i secret.enc -o secret.bin
```

## Security Notes

- **20! = 2,432,902,008,176,640,000** possible algorithm orderings
- **Argon2id** derives unique 256-bit keys per algorithm from master password
- **Random salt** ensures identical files encrypt differently
- **AEAD ciphers** (AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305, Ascon) provide authentication
- **Hybrid encryption** combines classical and post-quantum security for header protection
- **Quantum resistance**: Grover's algorithm halves effective key strength. 256-bit ciphers remain secure (128-bit post-quantum). Avoid using *only* 128-bit ciphers (`-F -I -4 -E -6 -J -N`) if quantum resistance matters—include at least one 256-bit cipher in your cascade.

## Performance

Tested on 1MB file through all 20 ciphers (Intel Xeon E-2176M @ 2.70GHz):
- Encryption: ~1.8s
- Decryption: ~1.9s

Bottlenecks: Argon2id key derivation (20 unique keys) and Serpent cipher.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and security updates.

## License

MIT
