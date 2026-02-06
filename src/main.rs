use anyhow::{Context, Result};
use rand::seq::SliceRandom;
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
    'A', 'T', 'W', 'S', 'C', 'X', 'M', 'B', 'F', 'I', 'R', '4', 'K', 'E', '3', '6', 'G', 'P', 'J',
    'N',
];

/// Algorithm long flag names (lowercase, without --) for case-insensitive matching
const ALGO_LONG_NAMES: &[&str] = &[
    "aes",
    "3des",
    "twofish",
    "serpent",
    "chacha",
    "xchacha",
    "camellia",
    "blowfish",
    "cast5",
    "idea",
    "aria",
    "sm4",
    "kuznyechik",
    "seed",
    "threefish",
    "rc6",
    "magma",
    "speck",
    "gift",
    "ascon",
];

/// Expand combined short flags like -ABC into -A -B -C
/// Also normalizes algorithm long flags to lowercase for case-insensitive matching
fn expand_combined_flags(args: Vec<String>) -> Vec<String> {
    let algo_chars = &ALGO_CHARS;
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
            if chars.iter().all(|c| algo_chars.contains(c)) {
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
    buffer::detect_cow_filesystem, decrypt_protected_with_buffer_mode, decrypt_with_buffer_mode,
    encrypt_protected_with_buffer_mode, encrypt_with_buffer_mode, Algorithm, BufferMode,
    HybridKeypair, HybridPrivateKey, HybridPublicKey,
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

// ===== CLI structures (no derive macros) =====

struct Cli {
    command: Option<Commands>,
    decrypt: bool,
    random_count: Option<usize>,
    silent: bool,
    progress: bool,
    lock: bool,
    list: bool,
    buffer_mode: Option<String>,
    aes: u8,
    triple_des: u8,
    twofish: u8,
    serpent: u8,
    chacha: u8,
    xchacha: u8,
    camellia: u8,
    blowfish: u8,
    cast5: u8,
    idea: u8,
    aria: u8,
    sm4: u8,
    kuznyechik: u8,
    seed: u8,
    threefish: u8,
    rc6: u8,
    magma: u8,
    speck: u8,
    gift: u8,
    ascon: u8,
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    keyfile: Option<PathBuf>,
    pubkey: Option<PathBuf>,
    privkey: Option<PathBuf>,
}

enum Commands {
    Keygen {
        output: PathBuf,
        export_pubkey: Option<PathBuf>,
    },
    ExportPubkey {
        input: PathBuf,
        output: PathBuf,
    },
}

// ===== Argument parsing =====

fn print_version() {
    println!("cascrypt {}", env!("CARGO_PKG_VERSION"));
}

fn print_help() {
    println!(
        "\
cascrypt {} — Cascading binary encryption tool

Encrypt binary files using multiple layered encryption algorithms.

Encryption algorithms are applied in the order specified on the command line.
Use -d to decrypt (algorithm order is auto-detected from file header).

Algorithm codes: A=AES, T=3DES, W=Twofish, S=Serpent, C=ChaCha20, X=XChaCha20,
M=Camellia, B=Blowfish, F=CAST5, I=IDEA, R=ARIA, 4=SM4, K=Kuznyechik, E=SEED,
3=Threefish, 6=RC6, G=Magma, P=Speck, J=GIFT, N=Ascon

Use 'keygen' subcommand to generate hybrid X25519+ML-KEM keypairs for header protection.

USAGE:
    cascrypt [OPTIONS] -i <FILE> -o <FILE>
    cascrypt keygen -o <FILE> [--export-pubkey <FILE>]
    cascrypt export-pubkey -i <FILE> -o <FILE>

OPTIONS:
    -d, --decrypt            Decrypt mode (encryption is default)
    -n, --random <N>         Use N randomly selected algorithms
    -s, --silent             Suppress all status output
        --progress           Show progress during encryption/decryption
        --lock               Engage puzzle lock (requires --pubkey)
        --list               List all available algorithms and exit
        --buffer <MODE>      Buffer mode: ram, disk, or auto (default)
    -i, --input <FILE>       Input file (use '-' for stdin)
    -o, --output <FILE>      Output file (use '-' for stdout)
        --keyfile <FILE>     Read key from file
        --pubkey <FILE>      Public key for header protection (encrypt)
        --privkey <FILE>     Private key for protected headers (decrypt)
    -h, --help               Print this help message
    -V, --version            Print version

ALGORITHMS:
    -A, --aes            AES-256-GCM                 [AEAD]
    -T, --3des           Triple-DES (3DES)           [Block]
    -W, --twofish        Twofish-256                 [Block]
    -S, --serpent        Serpent-256                  [Block]
    -C, --chacha         ChaCha20-Poly1305           [AEAD]
    -X, --xchacha        XChaCha20-Poly1305          [AEAD]
    -M, --camellia       Camellia-256                [Block]
    -B, --blowfish       Blowfish-256                [Block]
    -F, --cast5          CAST5                       [Block]
    -I, --idea           IDEA                        [Block]
    -R, --aria           ARIA-256                    [Block]
    -4, --sm4            SM4                         [Block]
    -K, --kuznyechik     Kuznyechik (GOST)           [Block]
    -E, --seed           SEED                        [Block]
    -3, --threefish      Threefish-256               [Block]
    -6, --rc6            RC6                         [Block]
    -G, --magma          Magma (GOST 28147-89)       [Block]
    -P, --speck          Speck128/256                [Block]
    -J, --gift           GIFT-128                    [Block]
    -N, --ascon          Ascon-128 (NIST 2023)       [AEAD]

Combine short flags: -ASC or -A -S -C
Repeat flags for multiple layers: -AAA or -A -A -A",
        env!("CARGO_PKG_VERSION")
    );
}

/// Take the next argument as a value for an option, or return an error.
fn take_value(args: &[String], i: &mut usize, flag: &str) -> Result<String> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("{} requires a value", flag))
}

/// Increment the counter for an algorithm short flag.
fn count_algo(cli: &mut Cli, code: char) {
    match code {
        'A' => cli.aes = cli.aes.saturating_add(1),
        'T' => cli.triple_des = cli.triple_des.saturating_add(1),
        'W' => cli.twofish = cli.twofish.saturating_add(1),
        'S' => cli.serpent = cli.serpent.saturating_add(1),
        'C' => cli.chacha = cli.chacha.saturating_add(1),
        'X' => cli.xchacha = cli.xchacha.saturating_add(1),
        'M' => cli.camellia = cli.camellia.saturating_add(1),
        'B' => cli.blowfish = cli.blowfish.saturating_add(1),
        'F' => cli.cast5 = cli.cast5.saturating_add(1),
        'I' => cli.idea = cli.idea.saturating_add(1),
        'R' => cli.aria = cli.aria.saturating_add(1),
        '4' => cli.sm4 = cli.sm4.saturating_add(1),
        'K' => cli.kuznyechik = cli.kuznyechik.saturating_add(1),
        'E' => cli.seed = cli.seed.saturating_add(1),
        '3' => cli.threefish = cli.threefish.saturating_add(1),
        '6' => cli.rc6 = cli.rc6.saturating_add(1),
        'G' => cli.magma = cli.magma.saturating_add(1),
        'P' => cli.speck = cli.speck.saturating_add(1),
        'J' => cli.gift = cli.gift.saturating_add(1),
        'N' => cli.ascon = cli.ascon.saturating_add(1),
        _ => {}
    }
}

/// Increment the counter for an algorithm long flag.
fn count_algo_long(cli: &mut Cli, name: &str) {
    match name {
        "aes" => cli.aes = cli.aes.saturating_add(1),
        "3des" => cli.triple_des = cli.triple_des.saturating_add(1),
        "twofish" => cli.twofish = cli.twofish.saturating_add(1),
        "serpent" => cli.serpent = cli.serpent.saturating_add(1),
        "chacha" => cli.chacha = cli.chacha.saturating_add(1),
        "xchacha" => cli.xchacha = cli.xchacha.saturating_add(1),
        "camellia" => cli.camellia = cli.camellia.saturating_add(1),
        "blowfish" => cli.blowfish = cli.blowfish.saturating_add(1),
        "cast5" => cli.cast5 = cli.cast5.saturating_add(1),
        "idea" => cli.idea = cli.idea.saturating_add(1),
        "aria" => cli.aria = cli.aria.saturating_add(1),
        "sm4" => cli.sm4 = cli.sm4.saturating_add(1),
        "kuznyechik" => cli.kuznyechik = cli.kuznyechik.saturating_add(1),
        "seed" => cli.seed = cli.seed.saturating_add(1),
        "threefish" => cli.threefish = cli.threefish.saturating_add(1),
        "rc6" => cli.rc6 = cli.rc6.saturating_add(1),
        "magma" => cli.magma = cli.magma.saturating_add(1),
        "speck" => cli.speck = cli.speck.saturating_add(1),
        "gift" => cli.gift = cli.gift.saturating_add(1),
        "ascon" => cli.ascon = cli.ascon.saturating_add(1),
        _ => {}
    }
}

fn parse_keygen(args: &[String], start: usize) -> Result<Commands> {
    let mut output: Option<PathBuf> = None;
    let mut export_pubkey: Option<PathBuf> = None;
    let mut i = start;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => output = Some(PathBuf::from(take_value(args, &mut i, "-o")?)),
            "--export-pubkey" => {
                export_pubkey = Some(PathBuf::from(take_value(args, &mut i, "--export-pubkey")?))
            }
            other => anyhow::bail!("Unknown option for keygen: {}", other),
        }
        i += 1;
    }
    let output = output.ok_or_else(|| anyhow::anyhow!("keygen requires -o <output>"))?;
    Ok(Commands::Keygen {
        output,
        export_pubkey,
    })
}

fn parse_export_pubkey(args: &[String], start: usize) -> Result<Commands> {
    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut i = start;
    while i < args.len() {
        match args[i].as_str() {
            "-i" | "--input" => input = Some(PathBuf::from(take_value(args, &mut i, "-i")?)),
            "-o" | "--output" => output = Some(PathBuf::from(take_value(args, &mut i, "-o")?)),
            other => anyhow::bail!("Unknown option for export-pubkey: {}", other),
        }
        i += 1;
    }
    let input = input.ok_or_else(|| anyhow::anyhow!("export-pubkey requires -i <input>"))?;
    let output = output.ok_or_else(|| anyhow::anyhow!("export-pubkey requires -o <output>"))?;
    Ok(Commands::ExportPubkey { input, output })
}

fn parse_cli(args: Vec<String>) -> Result<Cli> {
    let mut cli = Cli {
        command: None,
        decrypt: false,
        random_count: None,
        silent: false,
        progress: false,
        lock: false,
        list: false,
        buffer_mode: None,
        aes: 0,
        triple_des: 0,
        twofish: 0,
        serpent: 0,
        chacha: 0,
        xchacha: 0,
        camellia: 0,
        blowfish: 0,
        cast5: 0,
        idea: 0,
        aria: 0,
        sm4: 0,
        kuznyechik: 0,
        seed: 0,
        threefish: 0,
        rc6: 0,
        magma: 0,
        speck: 0,
        gift: 0,
        ascon: 0,
        input: None,
        output: None,
        keyfile: None,
        pubkey: None,
        privkey: None,
    };

    // args[0] is the binary name, skip it
    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            // Subcommands
            "keygen" => {
                cli.command = Some(parse_keygen(&args, i + 1)?);
                return Ok(cli);
            }
            "export-pubkey" => {
                cli.command = Some(parse_export_pubkey(&args, i + 1)?);
                return Ok(cli);
            }
            // Help/version (exit immediately)
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "-V" | "--version" => {
                print_version();
                std::process::exit(0);
            }
            // Boolean flags
            "-d" | "--decrypt" => cli.decrypt = true,
            "-s" | "--silent" => cli.silent = true,
            "--progress" => cli.progress = true,
            "--lock" => cli.lock = true,
            "--list" => cli.list = true,
            // Value flags
            "-n" | "--random" => {
                let val = take_value(&args, &mut i, "-n")?;
                cli.random_count = Some(
                    val.parse::<usize>()
                        .map_err(|_| anyhow::anyhow!("--random requires a number, got: {}", val))?,
                );
            }
            "-i" | "--input" => {
                cli.input = Some(PathBuf::from(take_value(&args, &mut i, "-i")?));
            }
            "-o" | "--output" => {
                cli.output = Some(PathBuf::from(take_value(&args, &mut i, "-o")?));
            }
            "--keyfile" => {
                cli.keyfile = Some(PathBuf::from(take_value(&args, &mut i, "--keyfile")?));
            }
            "--pubkey" => {
                cli.pubkey = Some(PathBuf::from(take_value(&args, &mut i, "--pubkey")?));
            }
            "--privkey" => {
                cli.privkey = Some(PathBuf::from(take_value(&args, &mut i, "--privkey")?));
            }
            "--buffer" => {
                cli.buffer_mode = Some(take_value(&args, &mut i, "--buffer")?);
            }
            // Algorithm short flags (single char after -)
            s if s.starts_with('-') && !s.starts_with("--") && s.len() == 2 => {
                let code = s.chars().nth(1).unwrap();
                if ALGO_CHARS.contains(&code) {
                    count_algo(&mut cli, code);
                } else {
                    anyhow::bail!("Unknown flag: {}", s);
                }
            }
            // Algorithm long flags
            s if s.starts_with("--") => {
                let name = &s[2..].to_lowercase();
                if ALGO_LONG_NAMES.contains(&name.as_str()) {
                    count_algo_long(&mut cli, name);
                } else {
                    anyhow::bail!("Unknown option: {}", s);
                }
            }
            other => {
                anyhow::bail!("Unexpected argument: {}", other);
            }
        }
        i += 1;
    }

    Ok(cli)
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
    let algo_chars = &ALGO_CHARS;
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
            if chars.iter().all(|c| algo_chars.contains(c)) {
                algorithms.extend(chars.iter().filter_map(|&c| Algorithm::from_code(c)));
            }
        }
    }

    algorithms
}

/// Generate N randomly selected algorithms (with duplicates allowed)
fn generate_random_algorithms(count: usize) -> Vec<Algorithm> {
    let mut rng = rand::thread_rng();
    (0..count)
        .map(|_| *ALL_ALGORITHMS.choose(&mut rng).unwrap())
        .collect()
}

/// Check if an algorithm provides authenticated encryption (AEAD)
fn is_aead(algo: Algorithm) -> bool {
    matches!(
        algo,
        Algorithm::Aes256
            | Algorithm::ChaCha20Poly1305
            | Algorithm::XChaCha20Poly1305
            | Algorithm::Ascon128
    )
}

/// Check if an algorithm uses a 64-bit block size (vulnerable to birthday attacks)
fn is_64bit_block(algo: Algorithm) -> bool {
    matches!(
        algo,
        Algorithm::TripleDes
            | Algorithm::Blowfish
            | Algorithm::Cast5
            | Algorithm::Idea
            | Algorithm::Magma
    )
}

/// Check if any individual algorithm flags were specified
fn has_algorithm_flags(cli: &Cli) -> bool {
    cli.aes > 0
        || cli.triple_des > 0
        || cli.twofish > 0
        || cli.serpent > 0
        || cli.chacha > 0
        || cli.xchacha > 0
        || cli.camellia > 0
        || cli.blowfish > 0
        || cli.cast5 > 0
        || cli.idea > 0
        || cli.aria > 0
        || cli.sm4 > 0
        || cli.kuznyechik > 0
        || cli.seed > 0
        || cli.threefish > 0
        || cli.rc6 > 0
        || cli.magma > 0
        || cli.speck > 0
        || cli.gift > 0
        || cli.ascon > 0
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
        let confirm = Zeroizing::new(
            rpassword::prompt_password("Confirm password: ").context("Failed to read password")?,
        );
        if password != *confirm {
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
        let data = fs::read(path)
            .with_context(|| format!("Failed to read input file: {}", path.display()))?;
        Ok(Zeroizing::new(data))
    }
}

fn write_output(path: &Path, data: &[u8]) -> Result<()> {
    if path.as_os_str() == "-" {
        io::stdout()
            .write_all(data)
            .context("Failed to write to stdout")?;
    } else {
        fs::write(path, data)
            .with_context(|| format!("Failed to write output file: {}", path.display()))?;
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

// ===== Simple progress =====

fn make_progress_cb(show: bool, label: &str) -> Box<dyn FnMut(usize, usize) + '_> {
    if show {
        Box::new(move |cur, total| {
            eprint!("\r{} {}/{}  ", label, cur, total);
        })
    } else {
        Box::new(|_, _| {})
    }
}

fn finish_progress(show: bool) {
    if show {
        eprintln!();
    }
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
        let long = LONG_FLAGS
            .iter()
            .find(|(_, a)| *a == algo)
            .map(|(l, _)| &l[2..]) // strip "--" prefix
            .unwrap_or("");
        println!(
            "  -{:<4} --{:<12} {:<21} {:<7} {}-bit",
            algo.code(),
            long,
            algo.name(),
            if is_aead(algo) { "AEAD" } else { "Block" },
            algo.key_size() * 8
        );
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

    // Warn about CoW filesystems when disk buffering may be used
    if !cli.silent && buffer_mode != BufferMode::Ram {
        if let Some(fs_name) = detect_cow_filesystem() {
            eprintln!(
                "󰀦 Warning: Temp directory is on {} (copy-on-write filesystem).",
                fs_name
            );
            eprintln!("   Secure deletion of temp files is not guaranteed.");
            eprintln!("   Consider --buffer=ram for sensitive data, or use full-disk encryption.");
        }
    }

    // Read input
    let input_data = read_input(&input)?;

    // Get password
    let password = get_password(&cli)?;

    let show_progress = cli.progress && !cli.silent;

    let output_data = if cli.decrypt {
        // Decrypt mode - algorithm order is in the header
        if let Some(privkey_path) = &cli.privkey {
            let private_key = load_private_key(privkey_path)?;
            if !cli.silent {
                eprintln!("󰦝 Decrypting with protected header...");
            }
            let result = decrypt_protected_with_buffer_mode(
                &input_data,
                &password,
                &private_key,
                buffer_mode,
                make_progress_cb(show_progress, "󰌊 Decrypting"),
            )
            .context("Decryption failed")?;
            finish_progress(show_progress);
            result
        } else {
            let result = decrypt_with_buffer_mode(
                &input_data,
                &password,
                buffer_mode,
                make_progress_cb(show_progress, "󰌊 Decrypting"),
            )
            .context("Decryption failed")?;
            finish_progress(show_progress);
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
                    format!(
                        ": {}",
                        algorithms
                            .iter()
                            .map(Algorithm::name)
                            .collect::<Vec<_>>()
                            .join(" → ")
                    )
                } else {
                    String::new()
                }
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
            let result = encrypt_protected_with_buffer_mode(
                &input_data,
                &password,
                &algorithms,
                &public_key,
                cli.lock,
                buffer_mode,
                make_progress_cb(show_progress, "󰌆 Encrypting"),
            )
            .context("Encryption failed")?;
            finish_progress(show_progress);
            result
        } else if cli.lock {
            anyhow::bail!("--lock requires --pubkey for protected header encryption");
        } else {
            let result = encrypt_with_buffer_mode(
                &input_data,
                &password,
                &algorithms,
                buffer_mode,
                make_progress_cb(show_progress, "󰌆 Encrypting"),
            )
            .context("Encryption failed")?;
            finish_progress(show_progress);
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
    let cli = parse_cli(expanded_args)?;

    match &cli.command {
        Some(Commands::Keygen {
            output,
            export_pubkey,
        }) => cmd_keygen(output, export_pubkey.as_deref()),
        Some(Commands::ExportPubkey { input, output }) => cmd_export_pubkey(input, output),
        None => cmd_encrypt_decrypt(cli),
    }
}
