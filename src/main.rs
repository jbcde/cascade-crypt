use anyhow::{Context, Result};
use clap::Parser;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use cascade_crypt::{decrypt, encrypt, Algorithm};

#[derive(Parser, Debug)]
#[command(name = "cascade-crypt")]
#[command(author, version, about = "Cascading binary encryption tool")]
#[command(long_about = "Encrypt binary files using multiple layered encryption algorithms.\n\n\
    Encryption algorithms are applied in the order specified on the command line.\n\
    Use -d to decrypt (algorithm order is auto-detected from file header).\n\n\
    Algorithm codes: A=AES, T=3DES, W=Twofish, S=Serpent, C=ChaCha20,\n\
    X=XChaCha20, M=Camellia, B=Blowfish, F=CAST5, I=IDEA, R=ARIA, 4=SM4, K=Kuznyechik")]
struct Args {
    /// Decrypt mode (encryption is default)
    #[arg(short = 'd', long = "decrypt")]
    decrypt: bool,

    // ===== Original algorithms =====
    /// Use AES-256-GCM encryption [code: A]
    #[arg(short = 'A', long = "aes")]
    aes: bool,

    /// Use Triple-DES (3DES) encryption [code: T]
    #[arg(short = 'T', long = "3des")]
    triple_des: bool,

    /// Use Twofish-256 encryption [code: W]
    #[arg(short = 'W', long = "twofish")]
    twofish: bool,

    /// Use Serpent-256 encryption [code: S]
    #[arg(short = 'S', long = "serpent")]
    serpent: bool,

    // ===== Stream ciphers =====
    /// Use ChaCha20-Poly1305 encryption [code: C]
    #[arg(short = 'C', long = "chacha")]
    chacha: bool,

    /// Use XChaCha20-Poly1305 encryption (extended nonce) [code: X]
    #[arg(short = 'X', long = "xchacha")]
    xchacha: bool,

    // ===== Additional block ciphers =====
    /// Use Camellia-256 encryption [code: M]
    #[arg(short = 'M', long = "camellia")]
    camellia: bool,

    /// Use Blowfish-256 encryption [code: B]
    #[arg(short = 'B', long = "blowfish")]
    blowfish: bool,

    /// Use CAST5 encryption [code: F]
    #[arg(short = 'F', long = "cast5")]
    cast5: bool,

    /// Use IDEA encryption [code: I]
    #[arg(short = 'I', long = "idea")]
    idea: bool,

    /// Use ARIA-256 encryption [code: R]
    #[arg(short = 'R', long = "aria")]
    aria: bool,

    /// Use SM4 encryption (Chinese standard) [code: 4]
    #[arg(short = '4', long = "sm4")]
    sm4: bool,

    /// Use Kuznyechik encryption (Russian GOST) [code: K]
    #[arg(short = 'K', long = "kuznyechik")]
    kuznyechik: bool,

    // ===== I/O options =====
    /// Input file (use '-' for stdin)
    #[arg(short = 'i', long = "input", required = true)]
    input: PathBuf,

    /// Output file (use '-' for stdout)
    #[arg(short = 'o', long = "output", required = true)]
    output: PathBuf,

    /// Encryption key/passphrase (prompts if not provided)
    #[arg(short = 'k', long = "key")]
    key: Option<String>,

    /// Read key from file
    #[arg(long = "keyfile")]
    keyfile: Option<PathBuf>,
}

/// Parse algorithm flags in the order they appear in argv
fn parse_algorithms_in_order() -> Vec<Algorithm> {
    let args: Vec<String> = std::env::args().collect();
    let mut algorithms = Vec::new();

    for arg in &args {
        match arg.as_str() {
            // Original algorithms
            "-A" | "--aes" => algorithms.push(Algorithm::Aes256),
            "-T" | "--3des" => algorithms.push(Algorithm::TripleDes),
            "-W" | "--twofish" => algorithms.push(Algorithm::Twofish),
            "-S" | "--serpent" => algorithms.push(Algorithm::Serpent),
            // Stream ciphers
            "-C" | "--chacha" => algorithms.push(Algorithm::ChaCha20Poly1305),
            "-X" | "--xchacha" => algorithms.push(Algorithm::XChaCha20Poly1305),
            // Additional block ciphers
            "-M" | "--camellia" => algorithms.push(Algorithm::Camellia),
            "-B" | "--blowfish" => algorithms.push(Algorithm::Blowfish),
            "-F" | "--cast5" => algorithms.push(Algorithm::Cast5),
            "-I" | "--idea" => algorithms.push(Algorithm::Idea),
            "-R" | "--aria" => algorithms.push(Algorithm::Aria),
            "-4" | "--sm4" => algorithms.push(Algorithm::Sm4),
            "-K" | "--kuznyechik" => algorithms.push(Algorithm::Kuznyechik),
            _ => {}
        }
    }

    algorithms
}

fn get_password(args: &Args) -> Result<Vec<u8>> {
    // Priority: keyfile > key argument > interactive prompt
    if let Some(keyfile) = &args.keyfile {
        let key = fs::read(keyfile).context("Failed to read keyfile")?;
        return Ok(key);
    }

    if let Some(key) = &args.key {
        return Ok(key.as_bytes().to_vec());
    }

    // Interactive prompt
    let prompt = if args.decrypt {
        "Enter decryption password: "
    } else {
        "Enter encryption password: "
    };

    let password = rpassword::prompt_password(prompt).context("Failed to read password")?;

    if !args.decrypt {
        let confirm =
            rpassword::prompt_password("Confirm password: ").context("Failed to read password")?;
        if password != confirm {
            anyhow::bail!("Passwords do not match");
        }
    }

    Ok(password.into_bytes())
}

fn read_input(path: &PathBuf) -> Result<Vec<u8>> {
    if path.as_os_str() == "-" {
        let mut data = Vec::new();
        io::stdin()
            .read_to_end(&mut data)
            .context("Failed to read from stdin")?;
        Ok(data)
    } else {
        fs::read(path).with_context(|| format!("Failed to read input file: {:?}", path))
    }
}

fn write_output(path: &PathBuf, data: &[u8]) -> Result<()> {
    if path.as_os_str() == "-" {
        io::stdout()
            .write_all(data)
            .context("Failed to write to stdout")?;
    } else {
        fs::write(path, data).with_context(|| format!("Failed to write output file: {:?}", path))?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Read input
    let input_data = read_input(&args.input)?;

    // Get password
    let password = get_password(&args)?;

    let output_data = if args.decrypt {
        // Decrypt mode - algorithm order is in the header
        decrypt(&input_data, &password).context("Decryption failed")?
    } else {
        // Encrypt mode - get algorithms in command-line order
        let algorithms = parse_algorithms_in_order();

        if algorithms.is_empty() {
            anyhow::bail!(
                "No encryption algorithms specified.\n\
                Use at least one of:\n\
                  -A (AES-256)      -T (3DES)         -W (Twofish)      -S (Serpent)\n\
                  -C (ChaCha20)     -X (XChaCha20)    -M (Camellia)     -B (Blowfish)\n\
                  -F (CAST5)        -I (IDEA)         -R (ARIA)         -4 (SM4)\n\
                  -K (Kuznyechik)"
            );
        }

        eprintln!(
            "Encrypting with: {}",
            algorithms
                .iter()
                .map(|a| a.name())
                .collect::<Vec<_>>()
                .join(" -> ")
        );

        encrypt(&input_data, &password, algorithms).context("Encryption failed")?
    };

    // Write output
    write_output(&args.output, &output_data)?;

    if args.decrypt {
        eprintln!("Decryption complete.");
    } else {
        eprintln!("Encryption complete.");
    }

    Ok(())
}
