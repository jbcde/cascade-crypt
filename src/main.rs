use anyhow::{Context, Result};
use clap::{ArgAction, Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use rand::seq::SliceRandom;
use std::collections::HashSet;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

fn init_thread_pool() {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    // Use half of available cores to leave headroom for system/IO
    let threads = (cores / 2).max(1);
    if let Err(e) = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
    {
        // Thread pool already initialized or resource error - continue with defaults
        eprintln!("Warning: Could not configure thread pool: {}", e);
    }
}

/// All algorithm short flag characters
const ALGO_CHARS: [char; 20] = [
    'A', 'T', 'W', 'S', 'C', 'X', 'M', 'B', 'F', 'I',
    'R', '4', 'K', 'E', '3', '6', 'G', 'P', 'J', 'N',
];

/// Algorithm long flag names (lowercase, without --) for case-insensitive matching
const ALGO_LONG_NAMES: &[&str] = &[
    "aes", "3des", "twofish", "serpent", "chacha", "xchacha", "camellia",
    "blowfish", "cast5", "idea", "aria", "sm4", "kuznyechik", "seed",
    "threefish", "rc6", "magma", "speck", "gift", "ascon",
];

/// Expand combined short flags like -ABC into -A -B -C
/// Also normalizes algorithm long flags to lowercase for case-insensitive matching
fn expand_combined_flags(args: Vec<String>) -> Vec<String> {
    let algo_set: HashSet<char> = ALGO_CHARS.into_iter().collect();
    let mut result = Vec::with_capacity(args.len());

    for arg in args {
        // Normalize algorithm long flags to lowercase (e.g., --AES -> --aes)
        if arg.starts_with("--") {
            let lower = arg.to_lowercase();
            if ALGO_LONG_NAMES.contains(&&lower[2..]) {
                result.push(lower);
                continue;
            }
        }
        // Check if this is a short flag group (starts with - but not --)
        // and has more than one character after the dash
        if arg.starts_with('-') && !arg.starts_with("--") && arg.len() > 2 {
            let chars: Vec<char> = arg[1..].chars().collect();
            // Only expand if ALL characters are algorithm flags
            if chars.iter().all(|c| algo_set.contains(c)) {
                for c in chars {
                    result.push(format!("-{}", c));
                }
                continue;
            }
        }
        result.push(arg);
    }

    result
}

use cascrypt::{
    decrypt_protected_with_buffer_mode, decrypt_with_buffer_mode,
    encrypt_protected_with_buffer_mode, encrypt_with_buffer_mode,
    Algorithm, BufferMode, HybridKeypair, HybridPrivateKey, HybridPublicKey,
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
#[command(name = "cascrypt")]
#[command(author, version, about = "Cascading binary encryption tool")]
#[command(long_about = "Encrypt binary files using multiple layered encryption algorithms.\n\n\
    Encryption algorithms are applied in the order specified on the command line.\n\
    Use -d to decrypt (algorithm order is auto-detected from file header).\n\n\
    Algorithm codes: A=AES, T=3DES, W=Twofish, S=Serpent, C=ChaCha20, X=XChaCha20,\n\
    M=Camellia, B=Blowfish, F=CAST5, I=IDEA, R=ARIA, 4=SM4, K=Kuznyechik, E=SEED, 3=Threefish,\n\
    6=RC6, G=Magma, P=Speck, J=GIFT, N=Ascon\n\n\
    Use 'keygen' subcommand to generate hybrid X25519+ML-KEM keypairs for header protection.")]
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

    /// Engage puzzle lock - obfuscation layer, NOT cryptographic security (requires --pubkey)
    #[arg(long = "lock")]
    lock: bool,

    /// List all available algorithms and exit
    #[arg(long = "list")]
    list: bool,

    /// Buffer mode: 'ram' (force RAM), 'disk' (force disk), 'auto' (default, switches under pressure)
    #[arg(long = "buffer", value_name = "MODE")]
    buffer_mode: Option<String>,

    // ===== Original algorithms =====
    /// Use AES-256-GCM encryption [code: A]
    #[arg(short = 'A', long = "aes", action = ArgAction::Count)]
    aes: u8,

    /// Use Triple-DES (3DES) encryption [code: T]
    #[arg(short = 'T', long = "3des", action = ArgAction::Count)]
    triple_des: u8,

    /// Use Twofish-256 encryption [code: W]
    #[arg(short = 'W', long = "twofish", action = ArgAction::Count)]
    twofish: u8,

    /// Use Serpent-256 encryption [code: S]
    #[arg(short = 'S', long = "serpent", action = ArgAction::Count)]
    serpent: u8,

    // ===== Stream ciphers =====
    /// Use ChaCha20-Poly1305 encryption [code: C]
    #[arg(short = 'C', long = "chacha", action = ArgAction::Count)]
    chacha: u8,

    /// Use XChaCha20-Poly1305 encryption (extended nonce) [code: X]
    #[arg(short = 'X', long = "xchacha", action = ArgAction::Count)]
    xchacha: u8,

    // ===== Additional block ciphers =====
    /// Use Camellia-256 encryption [code: M]
    #[arg(short = 'M', long = "camellia", action = ArgAction::Count)]
    camellia: u8,

    /// Use Blowfish-256 encryption [code: B]
    #[arg(short = 'B', long = "blowfish", action = ArgAction::Count)]
    blowfish: u8,

    /// Use CAST5 encryption [code: F]
    #[arg(short = 'F', long = "cast5", action = ArgAction::Count)]
    cast5: u8,

    /// Use IDEA encryption [code: I]
    #[arg(short = 'I', long = "idea", action = ArgAction::Count)]
    idea: u8,

    /// Use ARIA-256 encryption [code: R]
    #[arg(short = 'R', long = "aria", action = ArgAction::Count)]
    aria: u8,

    /// Use SM4 encryption (Chinese standard) [code: 4]
    #[arg(short = '4', long = "sm4", action = ArgAction::Count)]
    sm4: u8,

    /// Use Kuznyechik encryption (Russian GOST) [code: K]
    #[arg(short = 'K', long = "kuznyechik", action = ArgAction::Count)]
    kuznyechik: u8,

    /// Use SEED encryption (Korean standard) [code: E]
    #[arg(short = 'E', long = "seed", action = ArgAction::Count)]
    seed: u8,

    /// Use Threefish-256 encryption (Schneier's cipher) [code: 3]
    #[arg(short = '3', long = "threefish", action = ArgAction::Count)]
    threefish: u8,

    // ===== cipher 0.5 ciphers =====
    /// Use RC6 encryption (AES finalist) [code: 6]
    #[arg(short = '6', long = "rc6", action = ArgAction::Count)]
    rc6: u8,

    /// Use Magma encryption (Russian GOST 28147-89) [code: G]
    #[arg(short = 'G', long = "magma", action = ArgAction::Count)]
    magma: u8,

    /// Use Speck128/256 encryption (NSA lightweight) [code: P]
    #[arg(short = 'P', long = "speck", action = ArgAction::Count)]
    speck: u8,

    /// Use GIFT-128 encryption (lightweight cipher) [code: J]
    #[arg(short = 'J', long = "gift", action = ArgAction::Count)]
    gift: u8,

    /// Use Ascon-128 encryption (NIST 2023 winner) [code: N]
    #[arg(short = 'N', long = "ascon", action = ArgAction::Count)]
    ascon: u8,

    // ===== I/O options =====
    /// Input file (use '-' for stdin)
    #[arg(short = 'i', long = "input")]
    input: Option<PathBuf>,

    /// Output file (use '-' for stdout)
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,

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
    /// Generate a new hybrid X25519+ML-KEM keypair for header protection
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

/// Long flag name to Algorithm mapping
const LONG_FLAGS: &[(&str, Algorithm)] = &[
    ("--aes", Algorithm::Aes256),
    ("--3des", Algorithm::TripleDes),
    ("--twofish", Algorithm::Twofish),
    ("--serpent", Algorithm::Serpent),
    ("--chacha", Algorithm::ChaCha20Poly1305),
    ("--xchacha", Algorithm::XChaCha20Poly1305),
    ("--camellia", Algorithm::Camellia),
    ("--blowfish", Algorithm::Blowfish),
    ("--cast5", Algorithm::Cast5),
    ("--idea", Algorithm::Idea),
    ("--aria", Algorithm::Aria),
    ("--sm4", Algorithm::Sm4),
    ("--kuznyechik", Algorithm::Kuznyechik),
    ("--seed", Algorithm::Seed),
    ("--threefish", Algorithm::Threefish256),
    ("--rc6", Algorithm::Rc6),
    ("--magma", Algorithm::Magma),
    ("--speck", Algorithm::Speck128_256),
    ("--gift", Algorithm::Gift128),
    ("--ascon", Algorithm::Ascon128),
];

/// Parse algorithm flags in the order they appear in argv
/// Supports both individual flags (-A -S -C) and combined flags (-ASC)
/// Long flags are matched case-insensitively
fn parse_algorithms_in_order() -> Vec<Algorithm> {
    let algo_set: HashSet<char> = ALGO_CHARS.into_iter().collect();
    let mut algorithms = Vec::new();

    for arg in std::env::args() {
        // Check long flags first (case-insensitive)
        if arg.starts_with("--") {
            let lower = arg.to_lowercase();
            if let Some(&(_, algo)) = LONG_FLAGS.iter().find(|(flag, _)| *flag == lower) {
                algorithms.push(algo);
                continue;
            }
        }
        // Handle short flags: both single (-A) and combined (-ASC)
        if arg.starts_with('-') && !arg.starts_with("--") {
            let chars: Vec<char> = arg[1..].chars().collect();
            if chars.iter().all(|c| algo_set.contains(c)) {
                algorithms.extend(chars.iter().filter_map(|&c| Algorithm::from_code(c)));
            }
        }
    }

    algorithms
}

/// Generate N randomly selected algorithms (with duplicates allowed)
fn generate_random_algorithms(count: usize) -> Vec<Algorithm> {
    let mut rng = rand::thread_rng();
    (0..count).map(|_| *ALL_ALGORITHMS.choose(&mut rng).unwrap()).collect()
}

/// Check if an algorithm provides authenticated encryption (AEAD)
fn is_aead(algo: Algorithm) -> bool {
    matches!(algo,
        Algorithm::Aes256 | Algorithm::ChaCha20Poly1305 |
        Algorithm::XChaCha20Poly1305 | Algorithm::Ascon128)
}

/// Check if an algorithm uses a 64-bit block size (vulnerable to birthday attacks)
fn is_64bit_block(algo: Algorithm) -> bool {
    matches!(algo,
        Algorithm::TripleDes | Algorithm::Blowfish | Algorithm::Cast5 |
        Algorithm::Idea | Algorithm::Magma)
}

/// Check if any individual algorithm flags were specified
fn has_algorithm_flags(cli: &Cli) -> bool {
    cli.aes > 0 || cli.triple_des > 0 || cli.twofish > 0 || cli.serpent > 0
        || cli.chacha > 0 || cli.xchacha > 0 || cli.camellia > 0 || cli.blowfish > 0
        || cli.cast5 > 0 || cli.idea > 0 || cli.aria > 0 || cli.sm4 > 0 || cli.kuznyechik > 0
        || cli.seed > 0 || cli.threefish > 0 || cli.rc6 > 0 || cli.magma > 0 || cli.speck > 0
        || cli.gift > 0 || cli.ascon > 0
}

fn get_password(cli: &Cli) -> Result<Zeroizing<Vec<u8>>> {
    // Priority: keyfile > interactive prompt
    if let Some(keyfile) = &cli.keyfile {
        let key = fs::read(keyfile).context("Failed to read keyfile")?;
        return Ok(Zeroizing::new(key));
    }

    // Interactive prompt (no echo)
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

fn cmd_keygen(output: &Path, export_pubkey: Option<&Path>) -> Result<()> {
    eprintln!("󰌆 Generating hybrid X25519 + ML-KEM-1024 keypair...");

    let keypair = HybridKeypair::generate();
    let json = keypair.to_json().context("Failed to serialize keypair")?;

    fs::write(output, &json).with_context(|| format!("Failed to write keypair to {:?}", output))?;
    eprintln!("✓ Keypair saved to: {:?}", output);

    // Optionally export public key
    if let Some(pubkey_path) = export_pubkey {
        let pubkey_json = keypair
            .public
            .to_json()
            .context("Failed to serialize public key")?;
        fs::write(pubkey_path, &pubkey_json)
            .with_context(|| format!("Failed to write public key to {:?}", pubkey_path))?;
        eprintln!("✓ Public key exported to: {:?}", pubkey_path);
    }

    eprintln!("\n󰯄 Keypair contains:");
    eprintln!("  󰻧 X25519 (classical elliptic curve)");
    eprintln!("  󱉧 ML-KEM-1024 (post-quantum lattice-based)");
    eprintln!("\n󰒍 Share the public key with others for encrypted headers.");
    eprintln!("󰌾 Keep the full keypair private for decryption.");

    Ok(())
}

fn cmd_export_pubkey(input: &Path, output: &Path) -> Result<()> {
    let json = fs::read_to_string(input)
        .with_context(|| format!("Failed to read keypair file: {:?}", input))?;

    let keypair = HybridKeypair::from_json(&json).context("Failed to parse keypair")?;
    let pubkey_json = keypair
        .public
        .to_json()
        .context("Failed to serialize public key")?;

    fs::write(output, &pubkey_json)
        .with_context(|| format!("Failed to write public key to {:?}", output))?;

    eprintln!("✓ Public key exported to: {:?}", output);
    Ok(())
}

fn cmd_list_algorithms() {
    println!("Available encryption algorithms:\n");
    println!("  Flag  Long           Algorithm             Type    Key Size");
    println!("  ────  ────────────   ─────────────────     ─────   ────────");
    for algo in ALL_ALGORITHMS {
        let long = LONG_FLAGS.iter()
            .find(|(_, a)| *a == algo)
            .map(|(l, _)| &l[2..])  // strip "--" prefix
            .unwrap_or("");
        println!("  -{:<4} --{:<12} {:<21} {:<7} {}-bit",
            algo.code(), long, algo.name(),
            if is_aead(algo) { "AEAD" } else { "Block" },
            algo.key_size() * 8);
    }
    println!("\nUse flags in any order. Combine short flags: -ASC or -A -S -C");
    println!("Repeat flags for multiple layers: -AAA or -A -A -A");
}

fn cmd_encrypt_decrypt(cli: Cli) -> Result<()> {
    // Handle --list before requiring input/output
    if cli.list {
        cmd_list_algorithms();
        return Ok(());
    }

    // Validate required arguments for encrypt/decrypt mode
    let input = cli
        .input
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Input file required (-i)"))?;
    let output = cli
        .output
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Output file required (-o)"))?;

    // Parse buffer mode
    let buffer_mode = match cli.buffer_mode.as_deref() {
        Some(s) => s.parse::<BufferMode>().map_err(|e| anyhow::anyhow!(e))?,
        None => BufferMode::Auto,
    };

    // Read input
    let input_data = read_input(&input)?;

    // Get password
    let password = get_password(&cli)?;

    let show_progress = cli.progress && !cli.silent;

    let output_data = if cli.decrypt {
        // Decrypt mode - algorithm order is in the header
        if let Some(privkey_path) = &cli.privkey {
            let private_key = load_private_key(privkey_path)?;
            if !cli.silent { eprintln!("󰦝 Decrypting with protected header..."); }
            let pb = if show_progress { Some(create_progress_bar(100, "󰌊 Decrypting")) } else { None };
            let result = decrypt_protected_with_buffer_mode(&input_data, &password, &private_key, buffer_mode, |cur, total| {
                if let Some(pb) = &pb { pb.set_length(total as u64); pb.set_position(cur as u64); }
            }).context("Decryption failed")?;
            if let Some(pb) = pb { pb.finish(); }
            result
        } else {
            let pb = if show_progress { Some(create_progress_bar(100, "󰌊 Decrypting")) } else { None };
            let result = decrypt_with_buffer_mode(&input_data, &password, buffer_mode, |cur, total| {
                if let Some(pb) = &pb { pb.set_length(total as u64); pb.set_position(cur as u64); }
            }).context("Decryption failed")?;
            if let Some(pb) = pb { pb.finish(); }
            result
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
                    format!(": {}", algorithms.iter().map(Algorithm::name).collect::<Vec<_>>().join(" → "))
                } else { String::new() }
            );
            // Warn if outer layer lacks authentication
            if let Some(last) = algorithms.last() {
                if !is_aead(*last) {
                    eprintln!("󰀦 Warning: Outer layer ({}) is not AEAD - consider ending with -A, -C, -X, or -N for authentication", last.name());
                }
            }
            // Warn about 64-bit block ciphers (birthday attack vulnerability)
            let weak_ciphers: Vec<_> = algorithms.iter().filter(|a| is_64bit_block(**a)).collect();
            if !weak_ciphers.is_empty() {
                let names: Vec<_> = weak_ciphers.iter().map(|a| a.name()).collect();
                eprintln!("󰀦 Warning: 64-bit block cipher{} ({}) - vulnerable to birthday attacks on large files (>32GB)",
                    if weak_ciphers.len() > 1 { "s" } else { "" },
                    names.join(", "));
            }
        }

        if let Some(pubkey_path) = &cli.pubkey {
            let public_key = load_public_key(pubkey_path)?;
            if !cli.silent {
                if cli.lock {
                    eprintln!("󰌾 Using protected header with puzzle lock 󱡅");
                } else {
                    eprintln!("󰦝 Using protected header (hybrid X25519+ML-KEM encryption)");
                }
            }
            let pb = if show_progress { Some(create_progress_bar(algo_count as u64, "󰌆 Encrypting")) } else { None };
            let result = encrypt_protected_with_buffer_mode(&input_data, &password, algorithms, &public_key, cli.lock, buffer_mode, |cur, total| {
                if let Some(pb) = &pb { pb.set_length(total as u64); pb.set_position(cur as u64); }
            }).context("Encryption failed")?;
            if let Some(pb) = pb { pb.finish(); }
            result
        } else if cli.lock {
            anyhow::bail!("--lock requires --pubkey for protected header encryption");
        } else {
            let pb = if show_progress { Some(create_progress_bar(algo_count as u64, "󰌆 Encrypting")) } else { None };
            let result = encrypt_with_buffer_mode(&input_data, &password, algorithms, buffer_mode, |cur, total| {
                if let Some(pb) = &pb { pb.set_length(total as u64); pb.set_position(cur as u64); }
            }).context("Encryption failed")?;
            if let Some(pb) = pb { pb.finish(); }
            result
        }
    };

    // Write output
    write_output(&output, &output_data)?;

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
    init_thread_pool();
    let args: Vec<String> = std::env::args().collect();
    let expanded_args = expand_combined_flags(args);
    let cli = Cli::parse_from(expanded_args);

    match &cli.command {
        Some(Commands::Keygen {
            output,
            export_pubkey,
        }) => cmd_keygen(output, export_pubkey.as_deref()),
        Some(Commands::ExportPubkey { input, output }) => cmd_export_pubkey(input, output),
        None => cmd_encrypt_decrypt(cli),
    }
}
