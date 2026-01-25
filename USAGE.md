# cascrypt Usage Guide

## Quick Start

```bash
# Encrypt a file with AES + Serpent + ChaCha20
cascrypt -ASC -i input.bin -o output.enc -k "password"

# Decrypt
cascrypt -d -i output.enc -o decrypted.bin -k "password"
```

## Command Line Reference

```
cascrypt [OPTIONS] [COMMAND]

COMMANDS:
    keygen          Generate hybrid X25519+ML-KEM keypair
    export-pubkey   Export public key from keypair file
    help            Print help information

OPTIONS:
    -d, --decrypt               Decrypt mode (default is encrypt)
    -n, --random <COUNT>        Use N randomly selected algorithms
    -s, --silent                Suppress all status output
        --progress              Show progress bar during encryption/decryption
        --lock                  Engage puzzle lock (requires --pubkey)

    -A, --aes                   AES-256-GCM [code: A]
    -T, --3des                  Triple-DES-CBC [code: T]
    -W, --twofish               Twofish-256-CBC [code: W]
    -S, --serpent               Serpent-256-CBC [code: S]
    -C, --chacha                ChaCha20-Poly1305 [code: C]
    -X, --xchacha               XChaCha20-Poly1305 [code: X]
    -M, --camellia              Camellia-256-CBC [code: M]
    -B, --blowfish              Blowfish-256-CBC [code: B]
    -F, --cast5                 CAST5-CBC [code: F]
    -I, --idea                  IDEA-CBC [code: I]
    -R, --aria                  ARIA-256-CBC [code: R]
    -4, --sm4                   SM4-CBC [code: 4]
    -K, --kuznyechik            Kuznyechik-CBC [code: K]
    -E, --seed                  SEED-CBC [code: E]
    -3, --threefish             Threefish-256-CBC [code: 3]
    -6, --rc6                   RC6-CBC [code: 6]
    -G, --magma                 Magma-CBC (GOST) [code: G]
    -P, --speck                 Speck128/256-CBC [code: P]
    -J, --gift                  GIFT-128-CBC [code: J]
    -N, --ascon                 Ascon-128 [code: N]

    -i, --input <FILE>          Input file (use '-' for stdin)
    -o, --output <FILE>         Output file (use '-' for stdout)
    -k, --key <KEY>             Passphrase (prompts if omitted)
        --keyfile <FILE>        Read key from file
        --pubkey <FILE>         Public key for header protection
        --privkey <FILE>        Private key for protected headers

    -h, --help                  Print help
    -V, --version               Print version
```

## Encryption Modes

### Manual Algorithm Selection

Specify algorithms in the order you want them applied:

```bash
# Single algorithm
cascrypt -A -i file.bin -o file.enc

# Multiple algorithms (applied left to right)
cascrypt -ASCW -i file.bin -o file.enc
# Result: AES -> Serpent -> ChaCha20 -> Twofish

# Separate flags also work
cascrypt -A -S -C -W -i file.bin -o file.enc
```

Algorithm flags can be combined under a single `-` (e.g., `-ASC`) or specified separately (`-A -S -C`). Both styles can be mixed. Algorithms are applied in command-line order.

### Random Algorithm Selection

Use `-n` to randomly select N algorithms from all 20 available:

```bash
# 10 random layers
cascrypt -n 10 -i file.bin -o file.enc

# 100 random layers (duplicates expected)
cascrypt -n 100 -i file.bin -o file.enc

# 1000 layers for extreme paranoia
cascrypt -n 1000 -i file.bin -o file.enc
```

The `-n` flag:
- Selects from all 20 algorithms randomly
- Allows duplicates (same algorithm can appear multiple times)
- Has no upper limit
- Cannot be combined with manual algorithm flags

```bash
# ERROR: Cannot mix -n with algorithm flags
cascrypt -n 10 -A -i file.bin -o file.enc
```

## Decryption

Decryption is automatic - the algorithm order is stored in the file header:

```bash
# Basic decryption
cascrypt -d -i encrypted.enc -o decrypted.bin

# With password on command line
cascrypt -d -i encrypted.enc -o decrypted.bin -k "password"

# From keyfile
cascrypt -d -i encrypted.enc -o decrypted.bin --keyfile secret.key
```

## Silent Mode

Use `-s` to suppress all status output:

```bash
# Normal output
cascrypt -n 5 -i file.bin -o file.enc -k "pass"
# Output: Encrypting with: AES-256-GCM -> Serpent-256-CBC -> ...
#         Encryption complete.

# Silent output
cascrypt -s -n 5 -i file.bin -o file.enc -k "pass"
# Output: (nothing)
```

Silent mode suppresses:
- Algorithm chain display
- Protected header messages
- Completion messages

Errors are still printed to stderr.

### Security Use Case

Silent mode prevents shoulder-surfing and log capture of algorithm order:

```bash
# Maximum OPSEC: silent + random + protected header
cascrypt -s -n 50 --pubkey recipient.pub -i secret.bin -o secret.enc
```

## Progress Bar

Use `--progress` to display a progress bar during long encryption/decryption operations:

```bash
# Encrypt with progress bar
cascrypt --progress -n 100 -i file.bin -o file.enc -k "pass"
# Output: Encrypting with 100 algorithms
#         Encrypting [########################################] 100/100 (0s)
#         Encryption complete.

# Decrypt with progress bar
cascrypt --progress -d -i file.enc -o file.dec -k "pass"
```

The progress bar:
- Shows current layer and total layers
- Displays estimated time remaining
- Is disabled by default (opt-in with `--progress`)
- Is suppressed in silent mode (`-s` overrides `--progress`)

Useful for operations with many algorithm layers where you want visual feedback.

## Protected Headers (Hybrid Encryption)

By default, the file header reveals which algorithms were used. Protected headers encrypt this metadata.

### Generate Keypair

```bash
# Generate keypair
cascrypt keygen -o my.keypair

# Generate and export public key
cascrypt keygen -o my.keypair --export-pubkey my.pub

# Export public key from existing keypair
cascrypt export-pubkey -i my.keypair -o my.pub
```

The keypair uses:
- **X25519**: Classical elliptic curve (256-bit security)
- **ML-KEM-1024**: Post-quantum lattice KEM (NIST FIPS 203)

### Encrypt with Protected Header

```bash
cascrypt -A -S -C -i secret.bin -o secret.enc --pubkey recipient.pub
```

### Decrypt Protected Header

```bash
cascrypt -d -i secret.enc -o secret.bin --privkey my.keypair
```

### Combined with Random Mode

```bash
# Encrypt: random algorithms + protected header
cascrypt -n 30 --pubkey recipient.pub -i secret.bin -o secret.enc

# Decrypt
cascrypt -d --privkey my.keypair -i secret.enc -o secret.bin
```

### Puzzle Lock Mode

Use `--lock` with `--pubkey` to apply an additional transformation to the encrypted payload. This adds another layer of protection that requires the private key to reverse:

```bash
# Encrypt with puzzle lock
cascrypt -A -S -C --pubkey recipient.pub --lock -i secret.bin -o secret.enc

# Decrypt (requires private key)
cascrypt -d --privkey my.keypair -i secret.enc -o secret.bin -k "password"
```

The puzzle lock:
- Requires `--pubkey` (only works with protected headers)
- Applies a deterministic transformation to the encrypted data
- Cannot be decrypted without the matching private key
- Adds no significant overhead

## Password/Key Input

### Interactive Prompt

If no key is provided, you'll be prompted:

```bash
cascrypt -A -i file.bin -o file.enc
# Enter encryption password:
# Confirm password:
```

### Command Line

```bash
cascrypt -A -i file.bin -o file.enc -k "my password"
```

Note: Password visible in shell history and process list.

### Keyfile

```bash
# Use entire file contents as key
cascrypt -A -i file.bin -o file.enc --keyfile secret.key

# Binary keyfile works too
dd if=/dev/urandom of=secret.key bs=64 count=1
cascrypt -A -i file.bin -o file.enc --keyfile secret.key
```

## Stdin/Stdout

Use `-` for stdin or stdout:

```bash
# Encrypt from stdin
cat secret.txt | cascrypt -A -S -i - -o encrypted.bin -k "pass"

# Decrypt to stdout
cascrypt -d -i encrypted.bin -o - -k "pass" > decrypted.txt

# Both (pipe through)
cat secret.txt | cascrypt -A -i - -o - -k "pass" | base64
```

## Algorithm Reference

| Flag | Code | Algorithm | Type | Key Size |
|------|------|-----------|------|----------|
| `-A` | A | AES-256-GCM | AEAD | 256-bit |
| `-T` | T | 3DES-CBC | Block | 192-bit |
| `-W` | W | Twofish-256-CBC | Block | 256-bit |
| `-S` | S | Serpent-256-CBC | Block | 256-bit |
| `-C` | C | ChaCha20-Poly1305 | AEAD | 256-bit |
| `-X` | X | XChaCha20-Poly1305 | AEAD | 256-bit |
| `-M` | M | Camellia-256-CBC | Block | 256-bit |
| `-B` | B | Blowfish-256-CBC | Block | 256-bit |
| `-F` | F | CAST5-CBC | Block | 128-bit |
| `-I` | I | IDEA-CBC | Block | 128-bit |
| `-R` | R | ARIA-256-CBC | Block | 256-bit |
| `-4` | 4 | SM4-CBC | Block | 128-bit |
| `-K` | K | Kuznyechik-CBC | Block | 256-bit |
| `-E` | E | SEED-CBC | Block | 128-bit |
| `-3` | 3 | Threefish-256-CBC | Block | 256-bit |
| `-6` | 6 | RC6-CBC | Block | 128-bit |
| `-G` | G | Magma-CBC (GOST) | Block | 256-bit |
| `-P` | P | Speck128/256-CBC | Block | 256-bit |
| `-J` | J | GIFT-128-CBC | Block | 128-bit |
| `-N` | N | Ascon-128 | AEAD | 128-bit |

**AEAD** = Authenticated Encryption with Associated Data (provides integrity)
**Block** = CBC mode with PKCS7 padding

## Examples

### Basic Usage

```bash
# Simple encryption
cascrypt -A -i secret.txt -o secret.enc

# Decrypt
cascrypt -d -i secret.enc -o secret.txt
```

### Multi-Layer Encryption

```bash
# 4 algorithms
cascrypt -ATWS -i data.bin -o data.enc

# All 20 algorithms
cascrypt -ATWSCXMBFIR4KE36GPJN -i data.bin -o fortress.enc
```

### Random Encryption

```bash
# Quick random (5 layers)
cascrypt -n 5 -i file.bin -o file.enc

# Heavy random (50 layers)
cascrypt -n 50 -i file.bin -o file.enc

# Extreme (500 layers) with progress bar
cascrypt --progress -n 500 -i file.bin -o file.enc
```

### Secure Workflow

```bash
# Generate keys for Alice and Bob
cascrypt keygen -o alice.keypair --export-pubkey alice.pub
cascrypt keygen -o bob.keypair --export-pubkey bob.pub

# Alice encrypts for Bob (silent, random, protected)
cascrypt -s -n 30 --pubkey bob.pub -i message.txt -o message.enc -k "shared-secret"

# Bob decrypts
cascrypt -s -d --privkey bob.keypair -i message.enc -o message.txt -k "shared-secret"
```

### Scripting

```bash
# Silent mode for scripts (check exit code)
if cascrypt -s -A -i file.bin -o file.enc -k "$PASSWORD"; then
    echo "Encryption succeeded"
else
    echo "Encryption failed"
fi

# Process multiple files
for f in *.txt; do
    cascrypt -s -n 10 -i "$f" -o "${f}.enc" -k "$PASSWORD"
done
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Runtime error (encryption/decryption failure, missing files, etc.) |
| 2 | Argument error (invalid flags, missing required options) |

## File Format

### Version 7 (Plaintext Header)
```
[CCRYPT|7|<algo_codes>|<salt>|<argon2_params>|<ciphertext_hash>|<header_hash>]
<encrypted_data>
```

### Version 8 (Protected Header)
```
[CCRYPT|8|E|<encapsulated_keys>|<encrypted_metadata>|<ciphertext_hash>|<header_hash>]
<encrypted_data>
```

## Performance Tips

- AEAD ciphers (AES-GCM, ChaCha20, XChaCha20) are fastest
- 3DES is slowest (legacy algorithm)
- Argon2id key derivation runs once per algorithm layer
- For large files with many layers, expect linear slowdown

Approximate timing on Intel Xeon E-2176M @ 2.70GHz (1MB file):
- 1 algorithm: ~0.1s
- 20 algorithms: ~1.8s
- 100 algorithms: ~11s
