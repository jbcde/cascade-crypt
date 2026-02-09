use anyhow::{Context, Result};
use rand::seq::SliceRandom;
use std::fs;
use std::io::{self, Read, Seek, Write};
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


/// Expand combined short flags like -ABC into -A -B -C
/// Also normalizes algorithm long flags to lowercase for case-insensitive matching
fn expand_combined_flags(args: Vec<String>) -> Vec<String> {
    let algo_chars = &ALGO_CHARS;
    let mut result = Vec::with_capacity(args.len());

    for arg in args {
        // Normalize algorithm long flags to lowercase (e.g., --AES -> --aes)
        if arg.starts_with("--") {
            let lower = arg.to_lowercase();
            if LONG_FLAGS.iter().any(|(f, _)| *f == lower) {
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
    buffer::detect_cow_filesystem, chunked, decrypt_protected_with_buffer_mode,
    decrypt_with_buffer_mode, encrypt_protected_with_buffer_mode, encrypt_with_buffer_mode,
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
    chunk_size: Option<usize>,
    algorithms: Vec<Algorithm>,
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
        --chunk <SIZE>       Force chunked encryption (e.g. 512k, 100m, 4g)
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

/// Parse a chunk size like "512k", "100m", or "4g" into bytes.
/// The suffix is case-insensitive. No space allowed between number and unit.
fn parse_chunk_arg(s: &str) -> Result<usize> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("--chunk requires a size like 512k, 100m, or 4g");
    }
    let (num_part, suffix) = match s.as_bytes().last() {
        Some(b'k' | b'K') => (&s[..s.len() - 1], 1024usize),
        Some(b'm' | b'M') => (&s[..s.len() - 1], 1024 * 1024),
        Some(b'g' | b'G') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => anyhow::bail!("--chunk value must end with k, m, or g (e.g. 512k, 100m, 4g)"),
    };
    let n: usize = num_part
        .parse()
        .map_err(|_| anyhow::anyhow!("--chunk: invalid number in '{}' (use e.g. 512k, 100m, 4g)", s))?;
    if n == 0 {
        anyhow::bail!("--chunk size must be greater than zero");
    }
    Ok(n.checked_mul(suffix)
        .ok_or_else(|| anyhow::anyhow!("--chunk size overflows: {}", s))?)
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
        chunk_size: None,
        algorithms: Vec::new(),
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
            "--chunk" => {
                let val = take_value(&args, &mut i, "--chunk")?;
                cli.chunk_size = Some(parse_chunk_arg(&val)?);
            }
            // Algorithm short flags (single char after -)
            s if s.starts_with('-') && !s.starts_with("--") && s.len() == 2 => {
                let code = s.chars().nth(1).unwrap();
                if let Some(algo) = Algorithm::from_code(code) {
                    cli.algorithms.push(algo);
                } else {
                    anyhow::bail!("Unknown flag: {}", s);
                }
            }
            // Algorithm long flags
            s if s.starts_with("--") => {
                let name = s[2..].to_lowercase();
                if let Some(&(_, algo)) = LONG_FLAGS.iter().find(|(f, _)| f[2..] == *name) {
                    cli.algorithms.push(algo);
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

    let password = Zeroizing::new(
        rpassword::prompt_password(prompt).context("Failed to read password")?
    );

    if !cli.decrypt {
        let confirm = Zeroizing::new(
            rpassword::prompt_password("Confirm password: ").context("Failed to read password")?,
        );
        if *password != *confirm {
            anyhow::bail!("Passwords do not match");
        }
    }

    Ok(Zeroizing::new(password.as_bytes().to_vec()))
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

/// Write a key file with restricted permissions (mode 0600 on Unix).
/// Private key material must not be world-readable.
fn write_key_file(path: &Path, data: &str) -> Result<()> {
    fs::write(path, data)
        .with_context(|| format!("Failed to write key file: {:?}", path))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("Failed to set permissions on {:?}", path))?;
    }
    Ok(())
}

fn cmd_keygen(output: &Path, export_pubkey: Option<&Path>) -> Result<()> {
    eprintln!("󰌆 Generating hybrid X25519 + ML-KEM-1024 keypair...");

    let keypair = HybridKeypair::generate();
    let json = keypair.to_json().context("Failed to serialize keypair")?;

    write_key_file(output, &json)?;
    eprintln!("✓ Keypair saved to: {:?}", output);

    // Optionally export public key
    if let Some(pubkey_path) = export_pubkey {
        let pubkey_json = keypair
            .public
            .to_json()
            .context("Failed to serialize public key")?;
        write_key_file(pubkey_path, &pubkey_json)?;
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

    write_key_file(output, &pubkey_json)?;

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

    // Get password before reading input (needed for both chunked and non-chunked)
    let password = get_password(&cli)?;
    let show_progress = cli.progress && !cli.silent;
    let is_stdin = input.as_os_str() == "-";
    let is_stdout = output.as_os_str() == "-";

    if cli.decrypt {
        // === DECRYPT PATH ===

        // For file input, peek at header to detect chunked format
        if !is_stdin {
            let mut file = fs::File::open(&input)
                .with_context(|| format!("Failed to open input: {}", input.display()))?;
            let mut peek = [0u8; 16];
            let n = file.read(&mut peek).context("Failed to read input")?;

            if peek[..n].starts_with(b"[CCRYPT|9|") || peek[..n].starts_with(b"[CCRYPT|10|") {
                // Chunked decrypt — streaming, no full-file load
                file.seek(io::SeekFrom::Start(0)).context("Failed to seek input")?;
                let private_key = cli.privkey.as_ref()
                    .map(|p| load_private_key(p))
                    .transpose()?;

                if !cli.silent {
                    eprintln!("󰌊 Decrypting chunked file...");
                }

                if is_stdout {
                    let mut stdout = io::stdout();
                    chunked::decrypt_chunked(
                        &mut file,
                        &mut stdout,
                        &password,
                        buffer_mode,
                        private_key.as_ref(),
                        make_progress_cb(show_progress, "󰌊 Decrypting chunk"),
                    )
                    .context("Chunked decryption failed")?;
                } else {
                    let mut out_file = fs::File::create(&output)
                        .with_context(|| format!("Failed to create output: {}", output.display()))?;
                    chunked::decrypt_chunked(
                        &mut file,
                        &mut out_file,
                        &password,
                        buffer_mode,
                        private_key.as_ref(),
                        make_progress_cb(show_progress, "󰌊 Decrypting chunk"),
                    )
                    .context("Chunked decryption failed")?;
                }

                finish_progress(show_progress);
                if !cli.silent {
                    eprintln!("✓ Decryption complete.");
                }
                return Ok(());
            }
        }

        // Non-chunked decrypt (existing path)
        let input_data = read_input(&input)?;
        let output_data = if let Some(privkey_path) = &cli.privkey {
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
        };
        write_output(&output, &output_data)?;
        if !cli.silent {
            eprintln!("✓ Decryption complete.");
        }
    } else {
        // === ENCRYPT PATH ===

        // Resolve algorithms first (needed for both chunked and non-chunked)
        let algorithms = if let Some(count) = cli.random_count {
            if !cli.algorithms.is_empty() {
                anyhow::bail!(
                    "Cannot use -n/--random with individual algorithm flags.\n\
                    Use either -n <count> OR specific algorithm flags, not both."
                );
            }
            if count == 0 {
                anyhow::bail!("Random count must be at least 1");
            }
            generate_random_algorithms(count)
        } else if cli.algorithms.is_empty() {
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
        } else {
            cli.algorithms
        };

        // Print algorithm info and warnings
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
            if let Some(last) = algorithms.last() {
                if !is_aead(*last) {
                    eprintln!("󰀦 Warning: Outer layer ({}) is not AEAD - consider ending with -A, -C, -X, or -N for authentication", last.name());
                }
            }
            let weak_ciphers: Vec<_> = algorithms.iter().filter(|a| is_64bit_block(**a)).collect();
            if !weak_ciphers.is_empty() {
                let names: Vec<_> = weak_ciphers.iter().map(|a| a.name()).collect();
                eprintln!("󰀦 Warning: 64-bit block cipher{} ({}) - vulnerable to birthday attacks on large files (>32GB)",
                    if weak_ciphers.len() > 1 { "s" } else { "" },
                    names.join(", "));
            }
        }

        // Determine if chunked encryption should be used
        let effective_chunk_size = if let Some(cs) = cli.chunk_size {
            // Explicit --chunk
            if is_stdin {
                anyhow::bail!("--chunk requires file input (not stdin)");
            }
            if is_stdout {
                anyhow::bail!("Chunked encryption requires file output (not stdout)");
            }
            Some(cs)
        } else if !is_stdin && !is_stdout {
            // Auto-detect based on file size vs available RAM
            let meta = fs::metadata(&input)
                .with_context(|| format!("Failed to stat input: {}", input.display()))?;
            chunked::should_chunk(meta.len())
        } else {
            None
        };

        if let Some(chunk_size) = effective_chunk_size {
            // Chunked encrypt — streaming, seekable output
            let file_size = fs::metadata(&input)
                .with_context(|| format!("Failed to stat input: {}", input.display()))?
                .len();
            let mut in_file = fs::File::open(&input)
                .with_context(|| format!("Failed to open input: {}", input.display()))?;
            let mut out_file = fs::File::create(&output)
                .with_context(|| format!("Failed to create output: {}", output.display()))?;

            let pubkey = cli.pubkey.as_ref()
                .map(|p| load_public_key(p))
                .transpose()?;

            if !cli.silent {
                let chunk_mb = chunk_size as f64 / (1024.0 * 1024.0);
                let chunks = if file_size == 0 { 1 } else {
                    ((file_size as usize) + chunk_size - 1) / chunk_size
                };
                eprintln!("󰌆 Chunked mode: {} chunks of {:.1} MiB", chunks, chunk_mb);
                if pubkey.is_some() {
                    eprintln!("󰦝 Using protected header (hybrid X25519+ML-KEM encryption)");
                }
            }

            if cli.lock {
                anyhow::bail!("--lock is not supported with chunked encryption");
            }

            chunked::encrypt_chunked(
                &mut in_file,
                &mut out_file,
                &password,
                &algorithms,
                chunk_size,
                file_size,
                false,
                buffer_mode,
                pubkey.as_ref(),
                make_progress_cb(show_progress, "󰌆 Encrypting chunk"),
            )
            .context("Chunked encryption failed")?;
            finish_progress(show_progress);
            if !cli.silent {
                eprintln!("✓ Encryption complete.");
            }
        } else {
            // Non-chunked encrypt (existing path)
            let input_data = read_input(&input)?;

            let output_data = if let Some(pubkey_path) = &cli.pubkey {
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
                Zeroizing::new(result)
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
                Zeroizing::new(result)
            };
            write_output(&output, &output_data)?;
            if !cli.silent {
                eprintln!("✓ Encryption complete.");
            }
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
