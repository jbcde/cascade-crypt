use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use rand::seq::SliceRandom;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use cascade_crypt::{
    decrypt, decrypt_protected, decrypt_protected_with_progress, decrypt_with_progress,
    encrypt, encrypt_protected, encrypt_protected_with_progress, encrypt_with_progress,
    Algorithm, HybridKeypair, HybridPrivateKey, HybridPublicKey,
};

const ALL_ALGORITHMS: [Algorithm; 20] = [
    Algorithm::Aes256,
    Algorithm::TripleDes,
    Algorithm::Twofish,
    Algorithm::Serpent,
    Algorithm::ChaCha20Poly1305,
    Algorithm::XChaCha20Poly1305,
    Algorithm::Camellia,
    Algorithm::Blowfish,
    Algorithm::Cast5,
    Algorithm::Idea,
    Algorithm::Aria,
    Algorithm::Sm4,
    Algorithm::Kuznyechik,
    Algorithm::Seed,
    Algorithm::Threefish256,
    Algorithm::Rc6,
    Algorithm::Magma,
    Algorithm::Speck128_256,
    Algorithm::Gift128,
    Algorithm::Ascon128,
];

#[derive(Parser, Debug)]
#[command(name = "cascade-crypt")]
#[command(author, version, about = "Cascading binary encryption tool")]
#[command(long_about = "Encrypt binary files using multiple layered encryption algorithms.\n\n\
    Encryption algorithms are applied in the order specified on the command line.\n\
    Use -d to decrypt (algorithm order is auto-detected from file header).\n\n\
    Algorithm codes: A=AES, T=3DES, W=Twofish, S=Serpent, C=ChaCha20, X=XChaCha20,\n\
    M=Camellia, B=Blowfish, F=CAST5, I=IDEA, R=ARIA, 4=SM4, K=Kuznyechik, E=SEED, 3=Threefish,\n\
    6=RC6, G=Magma, P=Speck, J=GIFT, N=Ascon\n\n\
    Use 'keygen' subcommand to generate hybrid X25519+Kyber keypairs for header protection.")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Decrypt mode (encryption is default)
    #[arg(short = 'd', long = "decrypt")]
    decrypt: bool,

    /// Use N randomly selected algorithms (with duplicates). Disables individual algorithm flags.
    #[arg(short = 'n', long = "random")]
    random_count: Option<usize>,

    /// Silent mode - suppress all status output (for security)
    #[arg(short = 's', long = "silent")]
    silent: bool,

    /// Show progress bar during encryption/decryption
    #[arg(long = "progress")]
    progress: bool,

    /// Engage puzzle lock (requires --pubkey)
    #[arg(long = "lock")]
    lock: bool,

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

    /// Use SEED encryption (Korean standard) [code: E]
    #[arg(short = 'E', long = "seed")]
    seed: bool,

    /// Use Threefish-256 encryption (Schneier's cipher) [code: 3]
    #[arg(short = '3', long = "threefish")]
    threefish: bool,

    // ===== cipher 0.5 ciphers =====
    /// Use RC6 encryption (AES finalist) [code: 6]
    #[arg(short = '6', long = "rc6")]
    rc6: bool,

    /// Use Magma encryption (Russian GOST 28147-89) [code: G]
    #[arg(short = 'G', long = "magma")]
    magma: bool,

    /// Use Speck128/256 encryption (NSA lightweight) [code: P]
    #[arg(short = 'P', long = "speck")]
    speck: bool,

    /// Use GIFT-128 encryption (lightweight cipher) [code: J]
    #[arg(short = 'J', long = "gift")]
    gift: bool,

    /// Use Ascon-128 encryption (NIST 2023 winner) [code: N]
    #[arg(short = 'N', long = "ascon")]
    ascon: bool,

    // ===== I/O options =====
    /// Input file (use '-' for stdin)
    #[arg(short = 'i', long = "input")]
    input: Option<PathBuf>,

    /// Output file (use '-' for stdout)
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,

    /// Encryption key/passphrase (prompts if not provided)
    #[arg(short = 'k', long = "key")]
    key: Option<String>,

    /// Read key from file
    #[arg(long = "keyfile")]
    keyfile: Option<PathBuf>,

    // ===== Hybrid encryption options =====
    /// Recipient's public key file for header protection (encrypt mode)
    #[arg(long = "pubkey")]
    pubkey: Option<PathBuf>,

    /// Private key file for decrypting protected headers (decrypt mode)
    #[arg(long = "privkey")]
    privkey: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a new hybrid X25519+Kyber keypair for header protection
    Keygen {
        /// Output file for the keypair (JSON format)
        #[arg(short = 'o', long = "output", required = true)]
        output: PathBuf,

        /// Also export public key to separate file
        #[arg(long = "export-pubkey")]
        export_pubkey: Option<PathBuf>,
    },

    /// Export public key from a keypair file
    ExportPubkey {
        /// Input keypair file
        #[arg(short = 'i', long = "input", required = true)]
        input: PathBuf,

        /// Output file for public key
        #[arg(short = 'o', long = "output", required = true)]
        output: PathBuf,
    },
}

/// Parse algorithm flags in the order they appear in argv
fn parse_algorithms_in_order() -> Vec<Algorithm> {
    let args: Vec<String> = std::env::args().collect();
    let mut algorithms = Vec::new();

    for arg in &args {
        match arg.as_str() {
            "-A" | "--aes" => algorithms.push(Algorithm::Aes256),
            "-T" | "--3des" => algorithms.push(Algorithm::TripleDes),
            "-W" | "--twofish" => algorithms.push(Algorithm::Twofish),
            "-S" | "--serpent" => algorithms.push(Algorithm::Serpent),
            "-C" | "--chacha" => algorithms.push(Algorithm::ChaCha20Poly1305),
            "-X" | "--xchacha" => algorithms.push(Algorithm::XChaCha20Poly1305),
            "-M" | "--camellia" => algorithms.push(Algorithm::Camellia),
            "-B" | "--blowfish" => algorithms.push(Algorithm::Blowfish),
            "-F" | "--cast5" => algorithms.push(Algorithm::Cast5),
            "-I" | "--idea" => algorithms.push(Algorithm::Idea),
            "-R" | "--aria" => algorithms.push(Algorithm::Aria),
            "-4" | "--sm4" => algorithms.push(Algorithm::Sm4),
            "-K" | "--kuznyechik" => algorithms.push(Algorithm::Kuznyechik),
            "-E" | "--seed" => algorithms.push(Algorithm::Seed),
            "-3" | "--threefish" => algorithms.push(Algorithm::Threefish256),
            "-6" | "--rc6" => algorithms.push(Algorithm::Rc6),
            "-G" | "--magma" => algorithms.push(Algorithm::Magma),
            "-P" | "--speck" => algorithms.push(Algorithm::Speck128_256),
            "-J" | "--gift" => algorithms.push(Algorithm::Gift128),
            "-N" | "--ascon" => algorithms.push(Algorithm::Ascon128),
            _ => {}
        }
    }

    algorithms
}

/// Generate N randomly selected algorithms (with duplicates allowed)
fn generate_random_algorithms(count: usize) -> Vec<Algorithm> {
    let mut rng = rand::thread_rng();
    (0..count).map(|_| *ALL_ALGORITHMS.choose(&mut rng).unwrap()).collect()
}

/// Check if any individual algorithm flags were specified
fn has_algorithm_flags(cli: &Cli) -> bool {
    cli.aes || cli.triple_des || cli.twofish || cli.serpent ||
    cli.chacha || cli.xchacha || cli.camellia || cli.blowfish ||
    cli.cast5 || cli.idea || cli.aria || cli.sm4 || cli.kuznyechik ||
    cli.seed || cli.threefish || cli.rc6 || cli.magma || cli.speck ||
    cli.gift || cli.ascon
}

fn get_password(cli: &Cli) -> Result<Zeroizing<Vec<u8>>> {
    // Priority: keyfile > key argument > interactive prompt
    if let Some(keyfile) = &cli.keyfile {
        let key = fs::read(keyfile).context("Failed to read keyfile")?;
        return Ok(Zeroizing::new(key));
    }

    if let Some(key) = &cli.key {
        return Ok(Zeroizing::new(key.as_bytes().to_vec()));
    }

    // Interactive prompt
    let prompt = if cli.decrypt {
        "Enter decryption password: "
    } else {
        "Enter encryption password: "
    };

    let password = rpassword::prompt_password(prompt).context("Failed to read password")?;

    if !cli.decrypt {
        let confirm =
            rpassword::prompt_password("Confirm password: ").context("Failed to read password")?;
        if password != confirm {
            anyhow::bail!("Passwords do not match");
        }
    }

    Ok(Zeroizing::new(password.into_bytes()))
}

fn read_input(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    if path.as_os_str() == "-" {
        let mut data = Vec::new();
        io::stdin()
            .read_to_end(&mut data)
            .context("Failed to read from stdin")?;
        Ok(Zeroizing::new(data))
    } else {
        let data = fs::read(path).with_context(|| format!("Failed to read input file: {}", path.display()))?;
        Ok(Zeroizing::new(data))
    }
}

fn write_output(path: &Path, data: &[u8]) -> Result<()> {
    if path.as_os_str() == "-" {
        io::stdout()
            .write_all(data)
            .context("Failed to write to stdout")?;
    } else {
        fs::write(path, data).with_context(|| format!("Failed to write output file: {}", path.display()))?;
    }
    Ok(())
}

fn load_public_key(path: &Path) -> Result<HybridPublicKey> {
    let json = fs::read_to_string(path)
        .with_context(|| format!("Failed to read public key file: {}", path.display()))?;
    HybridPublicKey::from_json(&json).context("Failed to parse public key")
}

fn load_private_key(path: &Path) -> Result<HybridPrivateKey> {
    let json = fs::read_to_string(path)
        .with_context(|| format!("Failed to read private key file: {}", path.display()))?;

    // Try parsing as full keypair first, then as just private key
    if let Ok(keypair) = HybridKeypair::from_json(&json) {
        return Ok(keypair.private);
    }

    HybridPrivateKey::from_json(&json).context("Failed to parse private key")
}

fn create_progress_bar(total: u64, msg: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    // Nerdfont: 󰌆 = nf-md-lock, 󰌊 = nf-md-lock_open, 󰥔 = nf-md-clock
    // Progress bar chars: ━ (filled), ╾ (current), ─ (empty)
    let template = if msg.contains("Decrypt") {
        "{spinner:.green} {msg:.bold.green} │{bar:40.green/dim}│ {pos}/{len} 󰥔 {elapsed}"
    } else {
        "{spinner:.cyan} {msg:.bold.cyan} │{bar:40.cyan/dim}│ {pos}/{len} 󰥔 {elapsed}"
    };
    pb.set_style(ProgressStyle::with_template(template)
        .unwrap()
        .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"])
        .progress_chars("━╾─"));
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(std::time::Duration::from_millis(80));
    pb
}

fn cmd_keygen(output: PathBuf, export_pubkey: Option<PathBuf>) -> Result<()> {
    eprintln!("󰌆 Generating hybrid X25519 + Kyber1024 keypair...");

    let keypair = HybridKeypair::generate();
    let json = keypair.to_json().context("Failed to serialize keypair")?;

    fs::write(&output, &json).with_context(|| format!("Failed to write keypair to {:?}", output))?;
    eprintln!("✓ Keypair saved to: {:?}", output);

    // Optionally export public key
    if let Some(pubkey_path) = export_pubkey {
        let pubkey_json = keypair
            .public
            .to_json()
            .context("Failed to serialize public key")?;
        fs::write(&pubkey_path, &pubkey_json)
            .with_context(|| format!("Failed to write public key to {:?}", pubkey_path))?;
        eprintln!("✓ Public key exported to: {:?}", pubkey_path);
    }

    eprintln!("\n󰯄 Keypair contains:");
    eprintln!("  󰻧 X25519 (classical elliptic curve)");
    eprintln!("  󱉧 Kyber1024 (post-quantum lattice-based)");
    eprintln!("\n󰒍 Share the public key with others for encrypted headers.");
    eprintln!("󰌾 Keep the full keypair private for decryption.");

    Ok(())
}

fn cmd_export_pubkey(input: PathBuf, output: PathBuf) -> Result<()> {
    let json = fs::read_to_string(&input)
        .with_context(|| format!("Failed to read keypair file: {:?}", input))?;

    let keypair = HybridKeypair::from_json(&json).context("Failed to parse keypair")?;
    let pubkey_json = keypair
        .public
        .to_json()
        .context("Failed to serialize public key")?;

    fs::write(&output, &pubkey_json)
        .with_context(|| format!("Failed to write public key to {:?}", output))?;

    eprintln!("✓ Public key exported to: {:?}", output);
    Ok(())
}

fn cmd_encrypt_decrypt(cli: Cli) -> Result<()> {
    // Validate required arguments for encrypt/decrypt mode
    let input = cli
        .input
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Input file required (-i)"))?;
    let output = cli
        .output
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Output file required (-o)"))?;

    // Read input
    let input_data = read_input(input)?;

    // Get password
    let password = get_password(&cli)?;

    let show_progress = cli.progress && !cli.silent;

    let output_data = if cli.decrypt {
        // Decrypt mode - algorithm order is in the header
        if let Some(privkey_path) = &cli.privkey {
            let private_key = load_private_key(privkey_path)?;
            if !cli.silent { eprintln!("󰦝 Decrypting with protected header..."); }
            if show_progress {
                let pb = create_progress_bar(100, "󰌊 Decrypting");
                let result = decrypt_protected_with_progress(&input_data, &password, &private_key, |cur, total| {
                    pb.set_length(total as u64); pb.set_position(cur as u64);
                }).context("Decryption failed")?;
                pb.finish();
                result
            } else {
                decrypt_protected(&input_data, &password, &private_key).context("Decryption failed")?
            }
        } else if show_progress {
            let pb = create_progress_bar(100, "󰌊 Decrypting");
            let result = decrypt_with_progress(&input_data, &password, |cur, total| {
                pb.set_length(total as u64); pb.set_position(cur as u64);
            }).context("Decryption failed")?;
            pb.finish();
            result
        } else {
            decrypt(&input_data, &password).context("Decryption failed")?
        }
    } else {
        // Encrypt mode - get algorithms
        let algorithms = if let Some(count) = cli.random_count {
            // Random mode - check for conflicting flags
            if has_algorithm_flags(&cli) {
                anyhow::bail!(
                    "Cannot use -n/--random with individual algorithm flags.\n\
                    Use either -n <count> OR specific algorithm flags, not both."
                );
            }
            if count == 0 {
                anyhow::bail!("Random count must be at least 1");
            }
            generate_random_algorithms(count)
        } else {
            // Manual mode - parse algorithms from command line
            let algos = parse_algorithms_in_order();
            if algos.is_empty() {
                anyhow::bail!(
                    "No encryption algorithms specified.\n\
                    Use at least one of:\n\
                      -A (AES-256)      -T (3DES)         -W (Twofish)      -S (Serpent)\n\
                      -C (ChaCha20)     -X (XChaCha20)    -M (Camellia)     -B (Blowfish)\n\
                      -F (CAST5)        -I (IDEA)         -R (ARIA)         -4 (SM4)\n\
                      -K (Kuznyechik)   -E (SEED)         -3 (Threefish)    -6 (RC6)\n\
                      -G (Magma)        -P (Speck)        -J (GIFT)         -N (Ascon)\n\
                    Or use -n <count> for random algorithm selection."
                );
            }
            algos
        };

        let algo_count = algorithms.len();
        if !cli.silent {
            eprintln!(
                "󰌆 Encrypting with {} algorithm{}{}",
                algo_count,
                if algo_count == 1 { "" } else { "s" },
                if algo_count <= 5 {
                    format!(": {}", algorithms.iter().map(|a| a.name()).collect::<Vec<_>>().join(" → "))
                } else { String::new() }
            );
        }

        if let Some(pubkey_path) = &cli.pubkey {
            let public_key = load_public_key(pubkey_path)?;
            if !cli.silent {
                if cli.lock {
                    eprintln!("󰌾 Using protected header with puzzle lock 󱡅");
                } else {
                    eprintln!("󰦝 Using protected header (hybrid X25519+Kyber encryption)");
                }
            }
            if show_progress {
                let pb = create_progress_bar(algo_count as u64, "󰌆 Encrypting");
                let result = encrypt_protected_with_progress(&input_data, &password, algorithms, &public_key, cli.lock, |cur, total| {
                    pb.set_length(total as u64); pb.set_position(cur as u64);
                }).context("Encryption failed")?;
                pb.finish();
                result
            } else {
                encrypt_protected(&input_data, &password, algorithms, &public_key, cli.lock).context("Encryption failed")?
            }
        } else if cli.lock {
            anyhow::bail!("--lock requires --pubkey for protected header encryption");
        } else if show_progress {
            let pb = create_progress_bar(algo_count as u64, "󰌆 Encrypting");
            let result = encrypt_with_progress(&input_data, &password, algorithms, |cur, total| {
                pb.set_length(total as u64); pb.set_position(cur as u64);
            }).context("Encryption failed")?;
            pb.finish();
            result
        } else {
            encrypt(&input_data, &password, algorithms).context("Encryption failed")?
        }
    };

    // Write output
    write_output(output, &output_data)?;

    if !cli.silent {
        if cli.decrypt {
            eprintln!("✓ Decryption complete.");
        } else {
            eprintln!("✓ Encryption complete.");
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Keygen {
            output,
            export_pubkey,
        }) => cmd_keygen(output.clone(), export_pubkey.clone()),
        Some(Commands::ExportPubkey { input, output }) => {
            cmd_export_pubkey(input.clone(), output.clone())
        }
        None => cmd_encrypt_decrypt(cli),
    }
}
