# cascrypt

Cascading binary encryption tool with user-controlled algorithm ordering. Encrypt files through multiple layers of encryption, applied in the order you specify.

## Features

- **20 symmetric ciphers** - mix and match in any order
- **Cascading encryption** - algorithms applied sequentially in command-line order
- **Combined flags** - use `-ASC` instead of `-A -S -C` for convenience
- **Random mode** - randomly select N algorithms (with duplicates) for unpredictable layering
- **Silent mode** - suppress all output for operational security
- **Progress bar** - optional visual feedback for long operations (`--progress`)
- **Auto-decryption** - header stores algorithm order, decryption reverses automatically
- **Argon2id key derivation** - unique keys derived per algorithm layer
- **SHA-256 integrity** - header hash detects tampering
- **Hybrid header protection** - optional X25519 + Kyber1024 encryption hides algorithm order

## Installation

```bash
cargo build --release
# Binary at ./target/release/cascrypt
```

## Usage

### Encrypt (manual algorithm selection)
```bash
cascrypt -ASC -i secret.bin -o secret.enc -k "password"
```
Encrypts with AES-256 → Serpent → ChaCha20 (in that order). Flags can be combined (`-ASC`) or separate (`-A -S -C`).

### Encrypt (random algorithm selection)
```bash
cascrypt -n 20 -i secret.bin -o secret.enc -k "password"
```
Encrypts with 20 randomly selected algorithms (duplicates allowed).

### Decrypt
```bash
cascrypt -d -i secret.enc -o secret.bin -k "password"
```
Algorithm order is read from the file header automatically.

### Silent mode
```bash
cascrypt -s -n 50 -i secret.bin -o secret.enc -k "password"
```
Suppresses all status output (algorithm chain, completion messages).

### Options
```
-d, --decrypt       Decrypt mode
-n, --random N      Use N randomly selected algorithms (disables manual flags)
-s, --silent        Suppress all status output
    --progress      Show progress bar for long operations
-i, --input FILE    Input file (use '-' for stdin)
-o, --output FILE   Output file (use '-' for stdout)
-k, --key KEY       Passphrase (prompts if omitted)
    --keyfile FILE  Read key from file
    --pubkey FILE   Recipient's public key for header protection (encrypt)
    --privkey FILE  Private key for protected headers (decrypt)
```

### Progress Bar & Status Icons

When using `--progress` or viewing status output, the terminal displays status icons. These require a [Nerd Font](https://www.nerdfonts.com/) to render correctly.

| Emoji | Nerd Font | Meaning |
|-------|-----------|---------|
| 🔒 | `nf-md-lock` | Encrypting / Generating keypair |
| 🔓 | `nf-md-lock_open` | Decrypting |
| 🛡️ | `nf-md-shield_lock` | Protected header active |
| 🔐 | `nf-md-lock_alert` | Keep keypair private / Puzzle lock mode |
| 🧩 | `nf-md-puzzle` | Puzzle lock feature |
| ⏱️ | `nf-md-clock` | ETA (time remaining) |
| 🔗 | `nf-md-key_chain` | Keypair contents |
| 🔷 | `nf-md-key_variant` | X25519 classical key |
| 🔶 | `nf-md-key_wireless` | Kyber1024 post-quantum key |
| 📤 | `nf-md-share_variant` | Share public key |

Progress bar example:
```
⠋ 🔒 Encrypting │━━━━━━━━━━╾─────────────│ 7/20 ⏱️ 2s
```

**Note:** Without a Nerd Font installed, you may see placeholder boxes instead of icons—functionality is unaffected.

## Algorithms

| Flag | Code | Algorithm | Block/Stream |
|------|------|-----------|--------------|
| `-A` | A | AES-256-GCM | Block (AEAD) |
| `-T` | T | 3DES-CBC | Block |
| `-W` | W | Twofish-256-CBC | Block |
| `-S` | S | Serpent-256-CBC | Block |
| `-C` | C | ChaCha20-Poly1305 | Stream (AEAD) |
| `-X` | X | XChaCha20-Poly1305 | Stream (AEAD) |
| `-M` | M | Camellia-256-CBC | Block |
| `-B` | B | Blowfish-256-CBC | Block |
| `-F` | F | CAST5-CBC | Block |
| `-I` | I | IDEA-CBC | Block |
| `-R` | R | ARIA-256-CBC | Block |
| `-4` | 4 | SM4-CBC | Block |
| `-K` | K | Kuznyechik-CBC | Block |
| `-E` | E | SEED-CBC | Block |
| `-3` | 3 | Threefish-256-CBC | Block |
| `-6` | 6 | RC6-CBC | Block |
| `-G` | G | Magma-CBC (GOST) | Block |
| `-P` | P | Speck128/256-CBC | Block |
| `-J` | J | GIFT-128-CBC | Block |
| `-N` | N | Ascon-128 | Block (AEAD) |

## Hybrid Header Protection

By default, the header exposes which algorithms were used (though not the password or keys). For maximum security, you can encrypt the header itself using hybrid asymmetric encryption.

### Why?

With a plaintext header, an attacker knows they need to break AES → Serpent → ChaCha20. With an encrypted header, they don't even know which of the 6+ billion possible algorithm combinations to attack.

### Key Generation

Generate a hybrid keypair (X25519 + Kyber1024):

```bash
# Generate keypair and export public key
cascrypt keygen -o my.keypair --export-pubkey my.pubkey

# Or export public key later
cascrypt export-pubkey -i my.keypair -o my.pubkey
```

The keypair combines:
- **X25519**: Classical elliptic curve Diffie-Hellman (256-bit security)
- **Kyber1024**: Post-quantum lattice-based KEM (NIST Level 5, quantum-resistant)

### Protected Encryption

Encrypt with a protected header using the recipient's public key:

```bash
cascrypt -ASC -i secret.bin -o secret.enc -k "password" --pubkey recipient.pubkey
```

The algorithm order and salt are now encrypted. An attacker sees only:
```
[CCRYPT|2|E|<encrypted_keys>|<encrypted_metadata>|<hash>]
```

### Protected Decryption

Decrypt using your private key (full keypair file):

```bash
cascrypt -d -i secret.enc -o secret.bin -k "password" --privkey my.keypair
```

Without the private key, decryption fails:
```
Error: Encrypted header requires private key
```

## File Format

### Version 1 (Plaintext Header)
```
[CCRYPT|1|ASCX|<salt_hex>|<sha256>]
<encrypted payload>
```

- **Version**: 1
- **Algorithm codes**: Letters indicating encryption order (visible)
- **Salt**: 32-byte random salt (hex encoded)
- **SHA-256**: Hash of algorithm codes + salt

### Version 2 (Encrypted Header)
```
[CCRYPT|2|E|<encapsulated_keys_b64>|<encrypted_payload_b64>|<sha256>]
<encrypted payload>
```

- **Version**: 2
- **E**: Marker for encrypted header
- **Encapsulated keys**: X25519 ephemeral public key + Kyber ciphertext (base64)
- **Encrypted payload**: Algorithm codes + salt encrypted with ChaCha20-Poly1305 (base64)
- **SHA-256**: Hash of encrypted components

## Examples

```bash
# Maximum paranoia - all 20 ciphers
cascrypt -ATWSCXMBFIR4KE36GPJN -i file.bin -o fortress.enc

# Quick and modern
cascrypt -CA -i file.bin -o file.enc

# Random 100-layer encryption with progress bar
cascrypt --progress -n 100 -i file.bin -o file.enc

# Silent random encryption with protected header (maximum OPSEC)
cascrypt -s -n 50 --pubkey recipient.pubkey -i secret.bin -o secret.enc

# Pipe from stdin
cat secret.txt | cascrypt -AS -i - -o - -k "pass" > encrypted.bin

# Protected header workflow
cascrypt keygen -o alice.keypair --export-pubkey alice.pubkey
cascrypt -ACS -i secret.bin -o secret.enc --pubkey alice.pubkey
cascrypt -d -i secret.enc -o secret.bin --privkey alice.keypair

# Silent decryption
cascrypt -s -d -i secret.enc -o secret.bin -k "password"
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

## License

MIT
