//! End-to-end integration tests for cascade-crypt CLI
//!
//! These tests invoke the actual binary and verify full encryption/decryption workflows.

use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};
use std::path::PathBuf;

/// Get path to the cascade-crypt binary
fn binary_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push("debug");
    path.push("cascade-crypt");
    path
}

/// Create a temporary file with given content
fn create_temp_file(name: &str, content: &[u8]) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("cascade_test_{}", name));
    fs::write(&path, content).expect("Failed to create temp file");
    path
}

/// Clean up temporary files
fn cleanup(paths: &[PathBuf]) {
    for path in paths {
        let _ = fs::remove_file(path);
    }
}

/// Run cascade-crypt with given arguments
fn run_cascade(args: &[&str]) -> std::process::Output {
    Command::new(binary_path())
        .args(args)
        .output()
        .expect("Failed to execute cascade-crypt")
}

/// Run cascade-crypt and expect success
fn run_cascade_ok(args: &[&str]) -> std::process::Output {
    let output = run_cascade(args);
    if !output.status.success() {
        eprintln!("STDOUT: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("STDERR: {}", String::from_utf8_lossy(&output.stderr));
        panic!("Command failed: cascade-crypt {}", args.join(" "));
    }
    output
}

/// Run cascade-crypt and expect failure
fn run_cascade_fail(args: &[&str]) -> std::process::Output {
    let output = run_cascade(args);
    assert!(!output.status.success(), "Expected command to fail: cascade-crypt {}", args.join(" "));
    output
}

// ============================================================================
// Basic Encryption/Decryption Tests
// ============================================================================

#[test]
fn test_single_algorithm_aes() {
    let input = create_temp_file("aes_input.txt", b"Hello, AES encryption!");
    let encrypted = create_temp_file("aes_encrypted.bin", b"");
    let decrypted = create_temp_file("aes_decrypted.txt", b"");

    run_cascade_ok(&["-A", "-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "testpass", "-s"]);
    run_cascade_ok(&["-d", "-i", encrypted.to_str().unwrap(), "-o", decrypted.to_str().unwrap(), "-k", "testpass", "-s"]);

    let original = fs::read(&input).unwrap();
    let result = fs::read(&decrypted).unwrap();
    assert_eq!(original, result, "Decrypted content should match original");

    cleanup(&[input, encrypted, decrypted]);
}

#[test]
fn test_single_algorithm_chacha() {
    let input = create_temp_file("chacha_input.txt", b"Hello, ChaCha20 encryption!");
    let encrypted = create_temp_file("chacha_encrypted.bin", b"");
    let decrypted = create_temp_file("chacha_decrypted.txt", b"");

    run_cascade_ok(&["-C", "-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "testpass", "-s"]);
    run_cascade_ok(&["-d", "-i", encrypted.to_str().unwrap(), "-o", decrypted.to_str().unwrap(), "-k", "testpass", "-s"]);

    assert_eq!(fs::read(&input).unwrap(), fs::read(&decrypted).unwrap());

    cleanup(&[input, encrypted, decrypted]);
}

#[test]
fn test_single_algorithm_serpent() {
    let input = create_temp_file("serpent_input.txt", b"Hello, Serpent encryption!");
    let encrypted = create_temp_file("serpent_encrypted.bin", b"");
    let decrypted = create_temp_file("serpent_decrypted.txt", b"");

    run_cascade_ok(&["-S", "-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "testpass", "-s"]);
    run_cascade_ok(&["-d", "-i", encrypted.to_str().unwrap(), "-o", decrypted.to_str().unwrap(), "-k", "testpass", "-s"]);

    assert_eq!(fs::read(&input).unwrap(), fs::read(&decrypted).unwrap());

    cleanup(&[input, encrypted, decrypted]);
}

// ============================================================================
// Multi-Algorithm Cascade Tests
// ============================================================================

#[test]
fn test_two_algorithm_cascade() {
    let input = create_temp_file("two_algo_input.txt", b"Two algorithm cascade test");
    let encrypted = create_temp_file("two_algo_encrypted.bin", b"");
    let decrypted = create_temp_file("two_algo_decrypted.txt", b"");

    run_cascade_ok(&["-A", "-S", "-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "testpass", "-s"]);
    run_cascade_ok(&["-d", "-i", encrypted.to_str().unwrap(), "-o", decrypted.to_str().unwrap(), "-k", "testpass", "-s"]);

    assert_eq!(fs::read(&input).unwrap(), fs::read(&decrypted).unwrap());

    cleanup(&[input, encrypted, decrypted]);
}

#[test]
fn test_three_algorithm_cascade() {
    let input = create_temp_file("three_algo_input.txt", b"Three algorithm cascade test");
    let encrypted = create_temp_file("three_algo_encrypted.bin", b"");
    let decrypted = create_temp_file("three_algo_decrypted.txt", b"");

    run_cascade_ok(&["-A", "-S", "-C", "-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "testpass", "-s"]);
    run_cascade_ok(&["-d", "-i", encrypted.to_str().unwrap(), "-o", decrypted.to_str().unwrap(), "-k", "testpass", "-s"]);

    assert_eq!(fs::read(&input).unwrap(), fs::read(&decrypted).unwrap());

    cleanup(&[input, encrypted, decrypted]);
}

#[test]
fn test_five_algorithm_cascade() {
    let input = create_temp_file("five_algo_input.txt", b"Five algorithm cascade test");
    let encrypted = create_temp_file("five_algo_encrypted.bin", b"");
    let decrypted = create_temp_file("five_algo_decrypted.txt", b"");

    run_cascade_ok(&["-A", "-T", "-W", "-S", "-C", "-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "testpass", "-s"]);
    run_cascade_ok(&["-d", "-i", encrypted.to_str().unwrap(), "-o", decrypted.to_str().unwrap(), "-k", "testpass", "-s"]);

    assert_eq!(fs::read(&input).unwrap(), fs::read(&decrypted).unwrap());

    cleanup(&[input, encrypted, decrypted]);
}

#[test]
fn test_all_twenty_algorithms() {
    let input = create_temp_file("twenty_algo_input.txt", b"All twenty algorithms!");
    let encrypted = create_temp_file("twenty_algo_encrypted.bin", b"");
    let decrypted = create_temp_file("twenty_algo_decrypted.txt", b"");

    run_cascade_ok(&[
        "-A", "-T", "-W", "-S", "-C", "-X", "-M", "-B", "-F", "-I",
        "-R", "-4", "-K", "-E", "-3", "-6", "-G", "-P", "-J", "-N",
        "-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "testpass", "-s"
    ]);
    run_cascade_ok(&["-d", "-i", encrypted.to_str().unwrap(), "-o", decrypted.to_str().unwrap(), "-k", "testpass", "-s"]);

    assert_eq!(fs::read(&input).unwrap(), fs::read(&decrypted).unwrap());

    cleanup(&[input, encrypted, decrypted]);
}

#[test]
fn test_duplicate_algorithms_via_random() {
    // Duplicate algorithms are achieved via -n random mode (which allows duplicates)
    // Testing with a small -n value that statistically will have duplicates
    let input = create_temp_file("dup_algo_input.txt", b"Duplicate algorithms test");
    let encrypted = create_temp_file("dup_algo_encrypted.bin", b"");
    let decrypted = create_temp_file("dup_algo_decrypted.txt", b"");

    // With 50 random selections from 20 algorithms, duplicates are guaranteed
    run_cascade_ok(&["-n", "50", "-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "testpass", "-s"]);
    run_cascade_ok(&["-d", "-i", encrypted.to_str().unwrap(), "-o", decrypted.to_str().unwrap(), "-k", "testpass", "-s"]);

    assert_eq!(fs::read(&input).unwrap(), fs::read(&decrypted).unwrap());

    cleanup(&[input, encrypted, decrypted]);
}

// ============================================================================
// Random Mode Tests
// ============================================================================

#[test]
fn test_random_single() {
    let input = create_temp_file("random1_input.txt", b"Random single algorithm");
    let encrypted = create_temp_file("random1_encrypted.bin", b"");
    let decrypted = create_temp_file("random1_decrypted.txt", b"");

    run_cascade_ok(&["-n", "1", "-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "testpass", "-s"]);
    run_cascade_ok(&["-d", "-i", encrypted.to_str().unwrap(), "-o", decrypted.to_str().unwrap(), "-k", "testpass", "-s"]);

    assert_eq!(fs::read(&input).unwrap(), fs::read(&decrypted).unwrap());

    cleanup(&[input, encrypted, decrypted]);
}

#[test]
fn test_random_five() {
    let input = create_temp_file("random5_input.txt", b"Random five algorithms");
    let encrypted = create_temp_file("random5_encrypted.bin", b"");
    let decrypted = create_temp_file("random5_decrypted.txt", b"");

    run_cascade_ok(&["-n", "5", "-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "testpass", "-s"]);
    run_cascade_ok(&["-d", "-i", encrypted.to_str().unwrap(), "-o", decrypted.to_str().unwrap(), "-k", "testpass", "-s"]);

    assert_eq!(fs::read(&input).unwrap(), fs::read(&decrypted).unwrap());

    cleanup(&[input, encrypted, decrypted]);
}

#[test]
fn test_random_twenty() {
    let input = create_temp_file("random20_input.txt", b"Random twenty algorithms");
    let encrypted = create_temp_file("random20_encrypted.bin", b"");
    let decrypted = create_temp_file("random20_decrypted.txt", b"");

    run_cascade_ok(&["-n", "20", "-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "testpass", "-s"]);
    run_cascade_ok(&["-d", "-i", encrypted.to_str().unwrap(), "-o", decrypted.to_str().unwrap(), "-k", "testpass", "-s"]);

    assert_eq!(fs::read(&input).unwrap(), fs::read(&decrypted).unwrap());

    cleanup(&[input, encrypted, decrypted]);
}

// ============================================================================
// Protected Header Tests
// ============================================================================

#[test]
fn test_protected_header_basic() {
    let input = create_temp_file("protected_input.txt", b"Protected header test");
    let encrypted = create_temp_file("protected_encrypted.bin", b"");
    let decrypted = create_temp_file("protected_decrypted.txt", b"");
    let keypair = create_temp_file("test_keypair.json", b"");
    let pubkey = create_temp_file("test_pubkey.json", b"");

    // Generate keypair
    run_cascade_ok(&["keygen", "-o", keypair.to_str().unwrap(), "--export-pubkey", pubkey.to_str().unwrap()]);

    // Encrypt with protected header
    run_cascade_ok(&["-A", "-S", "-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "testpass", "--pubkey", pubkey.to_str().unwrap(), "-s"]);

    // Decrypt with private key
    run_cascade_ok(&["-d", "-i", encrypted.to_str().unwrap(), "-o", decrypted.to_str().unwrap(), "-k", "testpass", "--privkey", keypair.to_str().unwrap(), "-s"]);

    assert_eq!(fs::read(&input).unwrap(), fs::read(&decrypted).unwrap());

    cleanup(&[input, encrypted, decrypted, keypair, pubkey]);
}

#[test]
fn test_protected_header_requires_privkey() {
    let input = create_temp_file("protected_req_input.txt", b"Protected header requires key");
    let encrypted = create_temp_file("protected_req_encrypted.bin", b"");
    let decrypted = create_temp_file("protected_req_decrypted.txt", b"");
    let keypair = create_temp_file("test_keypair2.json", b"");
    let pubkey = create_temp_file("test_pubkey2.json", b"");

    // Generate keypair
    run_cascade_ok(&["keygen", "-o", keypair.to_str().unwrap(), "--export-pubkey", pubkey.to_str().unwrap()]);

    // Encrypt with protected header
    run_cascade_ok(&["-A", "-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "testpass", "--pubkey", pubkey.to_str().unwrap(), "-s"]);

    // Try to decrypt WITHOUT private key - should fail
    run_cascade_fail(&["-d", "-i", encrypted.to_str().unwrap(), "-o", decrypted.to_str().unwrap(), "-k", "testpass", "-s"]);

    cleanup(&[input, encrypted, decrypted, keypair, pubkey]);
}

#[test]
fn test_protected_header_wrong_key() {
    let input = create_temp_file("protected_wrong_input.txt", b"Wrong key test");
    let encrypted = create_temp_file("protected_wrong_encrypted.bin", b"");
    let decrypted = create_temp_file("protected_wrong_decrypted.txt", b"");
    let keypair1 = create_temp_file("test_keypair_a.json", b"");
    let pubkey1 = create_temp_file("test_pubkey_a.json", b"");
    let keypair2 = create_temp_file("test_keypair_b.json", b"");

    // Generate two different keypairs
    run_cascade_ok(&["keygen", "-o", keypair1.to_str().unwrap(), "--export-pubkey", pubkey1.to_str().unwrap()]);
    run_cascade_ok(&["keygen", "-o", keypair2.to_str().unwrap()]);

    // Encrypt with keypair1's public key
    run_cascade_ok(&["-A", "-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "testpass", "--pubkey", pubkey1.to_str().unwrap(), "-s"]);

    // Try to decrypt with keypair2 - should fail
    run_cascade_fail(&["-d", "-i", encrypted.to_str().unwrap(), "-o", decrypted.to_str().unwrap(), "-k", "testpass", "--privkey", keypair2.to_str().unwrap(), "-s"]);

    cleanup(&[input, encrypted, decrypted, keypair1, pubkey1, keypair2]);
}

// ============================================================================
// Puzzle Lock Tests
// ============================================================================

#[test]
fn test_puzzle_lock() {
    let input = create_temp_file("puzzle_input.txt", b"Puzzle lock test data");
    let encrypted = create_temp_file("puzzle_encrypted.bin", b"");
    let decrypted = create_temp_file("puzzle_decrypted.txt", b"");
    let keypair = create_temp_file("puzzle_keypair.json", b"");
    let pubkey = create_temp_file("puzzle_pubkey.json", b"");

    // Generate keypair
    run_cascade_ok(&["keygen", "-o", keypair.to_str().unwrap(), "--export-pubkey", pubkey.to_str().unwrap()]);

    // Encrypt with puzzle lock
    run_cascade_ok(&["-A", "-S", "--lock", "-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "testpass", "--pubkey", pubkey.to_str().unwrap(), "-s"]);

    // Decrypt with private key
    run_cascade_ok(&["-d", "-i", encrypted.to_str().unwrap(), "-o", decrypted.to_str().unwrap(), "-k", "testpass", "--privkey", keypair.to_str().unwrap(), "-s"]);

    assert_eq!(fs::read(&input).unwrap(), fs::read(&decrypted).unwrap());

    cleanup(&[input, encrypted, decrypted, keypair, pubkey]);
}

#[test]
fn test_puzzle_lock_requires_pubkey() {
    let input = create_temp_file("puzzle_req_input.txt", b"Puzzle lock requires pubkey");
    let encrypted = create_temp_file("puzzle_req_encrypted.bin", b"");

    // Try to use --lock without --pubkey - should fail
    run_cascade_fail(&["-A", "--lock", "-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "testpass", "-s"]);

    cleanup(&[input, encrypted]);
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
fn test_wrong_password() {
    let input = create_temp_file("wrong_pw_input.txt", b"Wrong password test");
    let encrypted = create_temp_file("wrong_pw_encrypted.bin", b"");
    let decrypted = create_temp_file("wrong_pw_decrypted.txt", b"");

    run_cascade_ok(&["-A", "-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "correct", "-s"]);
    run_cascade_fail(&["-d", "-i", encrypted.to_str().unwrap(), "-o", decrypted.to_str().unwrap(), "-k", "wrong", "-s"]);

    cleanup(&[input, encrypted, decrypted]);
}

#[test]
fn test_no_algorithms_specified() {
    let input = create_temp_file("no_algo_input.txt", b"No algorithms");
    let encrypted = create_temp_file("no_algo_encrypted.bin", b"");

    // No algorithm flags - should fail
    run_cascade_fail(&["-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "testpass", "-s"]);

    cleanup(&[input, encrypted]);
}

#[test]
fn test_random_zero() {
    let input = create_temp_file("random0_input.txt", b"Random zero");
    let encrypted = create_temp_file("random0_encrypted.bin", b"");

    // -n 0 should fail
    run_cascade_fail(&["-n", "0", "-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "testpass", "-s"]);

    cleanup(&[input, encrypted]);
}

#[test]
fn test_random_with_algorithm_flags() {
    let input = create_temp_file("random_conflict_input.txt", b"Conflict test");
    let encrypted = create_temp_file("random_conflict_encrypted.bin", b"");

    // -n with algorithm flags should fail
    run_cascade_fail(&["-n", "5", "-A", "-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "testpass", "-s"]);

    cleanup(&[input, encrypted]);
}

#[test]
fn test_missing_input_file() {
    let encrypted = create_temp_file("missing_input_encrypted.bin", b"");

    run_cascade_fail(&["-A", "-i", "/nonexistent/file.txt", "-o", encrypted.to_str().unwrap(), "-k", "testpass", "-s"]);

    cleanup(&[encrypted]);
}

#[test]
fn test_corrupted_header() {
    let encrypted = create_temp_file("corrupted_header.bin", b"[CCRYPT|1|INVALID|badhash]\ncorrupted data");
    let decrypted = create_temp_file("corrupted_decrypted.txt", b"");

    run_cascade_fail(&["-d", "-i", encrypted.to_str().unwrap(), "-o", decrypted.to_str().unwrap(), "-k", "testpass", "-s"]);

    cleanup(&[encrypted, decrypted]);
}

// ============================================================================
// Binary Data Tests
// ============================================================================

#[test]
fn test_binary_data() {
    // All possible byte values
    let data: Vec<u8> = (0..=255).collect();
    let input = create_temp_file("binary_input.bin", &data);
    let encrypted = create_temp_file("binary_encrypted.bin", b"");
    let decrypted = create_temp_file("binary_decrypted.bin", b"");

    run_cascade_ok(&["-A", "-S", "-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "testpass", "-s"]);
    run_cascade_ok(&["-d", "-i", encrypted.to_str().unwrap(), "-o", decrypted.to_str().unwrap(), "-k", "testpass", "-s"]);

    assert_eq!(fs::read(&input).unwrap(), fs::read(&decrypted).unwrap());

    cleanup(&[input, encrypted, decrypted]);
}

#[test]
fn test_large_binary_data() {
    // 1MB of random-ish data
    let data: Vec<u8> = (0..1024*1024).map(|i| (i % 256) as u8).collect();
    let input = create_temp_file("large_input.bin", &data);
    let encrypted = create_temp_file("large_encrypted.bin", b"");
    let decrypted = create_temp_file("large_decrypted.bin", b"");

    run_cascade_ok(&["-A", "-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "testpass", "-s"]);
    run_cascade_ok(&["-d", "-i", encrypted.to_str().unwrap(), "-o", decrypted.to_str().unwrap(), "-k", "testpass", "-s"]);

    assert_eq!(fs::read(&input).unwrap(), fs::read(&decrypted).unwrap());

    cleanup(&[input, encrypted, decrypted]);
}

#[test]
fn test_empty_file() {
    let input = create_temp_file("empty_input.bin", b"");
    let encrypted = create_temp_file("empty_encrypted.bin", b"");
    let decrypted = create_temp_file("empty_decrypted.bin", b"");

    run_cascade_ok(&["-A", "-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "testpass", "-s"]);
    run_cascade_ok(&["-d", "-i", encrypted.to_str().unwrap(), "-o", decrypted.to_str().unwrap(), "-k", "testpass", "-s"]);

    assert_eq!(fs::read(&input).unwrap(), fs::read(&decrypted).unwrap());

    cleanup(&[input, encrypted, decrypted]);
}

// ============================================================================
// Stdin/Stdout Tests
// ============================================================================

#[test]
fn test_stdin_input() {
    let encrypted = create_temp_file("stdin_encrypted.bin", b"");
    let decrypted = create_temp_file("stdin_decrypted.txt", b"");
    let input_data = b"Data from stdin";

    // Encrypt from stdin
    let mut child = Command::new(binary_path())
        .args(&["-A", "-i", "-", "-o", encrypted.to_str().unwrap(), "-k", "testpass", "-s"])
        .stdin(Stdio::piped())
        .spawn()
        .expect("Failed to spawn process");

    child.stdin.as_mut().unwrap().write_all(input_data).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "Encryption from stdin failed");

    // Decrypt normally
    run_cascade_ok(&["-d", "-i", encrypted.to_str().unwrap(), "-o", decrypted.to_str().unwrap(), "-k", "testpass", "-s"]);

    assert_eq!(fs::read(&decrypted).unwrap(), input_data);

    cleanup(&[encrypted, decrypted]);
}

// ============================================================================
// Keygen Tests
// ============================================================================

#[test]
fn test_keygen_creates_valid_keypair() {
    let keypair = create_temp_file("keygen_test.json", b"");

    run_cascade_ok(&["keygen", "-o", keypair.to_str().unwrap()]);

    let content = fs::read_to_string(&keypair).unwrap();
    assert!(content.contains("x25519"), "Keypair should contain x25519 key");
    assert!(content.contains("kyber"), "Keypair should contain kyber key");

    cleanup(&[keypair]);
}

#[test]
fn test_keygen_with_pubkey_export() {
    let keypair = create_temp_file("keygen_full.json", b"");
    let pubkey = create_temp_file("keygen_pub.json", b"");

    run_cascade_ok(&["keygen", "-o", keypair.to_str().unwrap(), "--export-pubkey", pubkey.to_str().unwrap()]);

    let keypair_content = fs::read_to_string(&keypair).unwrap();
    let pubkey_content = fs::read_to_string(&pubkey).unwrap();

    // Keypair has both public and private
    assert!(keypair_content.contains("\"public\""), "Keypair should have public key");
    assert!(keypair_content.contains("\"private\""), "Keypair should have private key");

    // Public key file should only have public key data
    assert!(pubkey_content.contains("x25519"), "Public key should contain x25519");
    assert!(pubkey_content.contains("kyber"), "Public key should contain kyber");

    cleanup(&[keypair, pubkey]);
}

#[test]
fn test_export_pubkey_command() {
    let keypair = create_temp_file("export_test_keypair.json", b"");
    let pubkey = create_temp_file("export_test_pubkey.json", b"");

    // Generate keypair without export
    run_cascade_ok(&["keygen", "-o", keypair.to_str().unwrap()]);

    // Export public key separately
    run_cascade_ok(&["export-pubkey", "-i", keypair.to_str().unwrap(), "-o", pubkey.to_str().unwrap()]);

    let pubkey_content = fs::read_to_string(&pubkey).unwrap();
    assert!(pubkey_content.contains("x25519"), "Exported public key should contain x25519");

    cleanup(&[keypair, pubkey]);
}

// ============================================================================
// Algorithm-Specific Tests
// ============================================================================

#[test]
fn test_each_algorithm_individually() {
    let algos = [
        ("-A", "aes"), ("-T", "3des"), ("-W", "twofish"), ("-S", "serpent"),
        ("-C", "chacha"), ("-X", "xchacha"), ("-M", "camellia"), ("-B", "blowfish"),
        ("-F", "cast5"), ("-I", "idea"), ("-R", "aria"), ("-4", "sm4"),
        ("-K", "kuznyechik"), ("-E", "seed"), ("-3", "threefish"), ("-6", "rc6"),
        ("-G", "magma"), ("-P", "speck"), ("-J", "gift"), ("-N", "ascon"),
    ];

    for (flag, name) in algos {
        let input = create_temp_file(&format!("{}_input.txt", name), format!("Testing {}", name).as_bytes());
        let encrypted = create_temp_file(&format!("{}_encrypted.bin", name), b"");
        let decrypted = create_temp_file(&format!("{}_decrypted.txt", name), b"");

        run_cascade_ok(&[flag, "-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "testpass", "-s"]);
        run_cascade_ok(&["-d", "-i", encrypted.to_str().unwrap(), "-o", decrypted.to_str().unwrap(), "-k", "testpass", "-s"]);

        assert_eq!(fs::read(&input).unwrap(), fs::read(&decrypted).unwrap(), "Algorithm {} failed roundtrip", name);

        cleanup(&[input, encrypted, decrypted]);
    }
}

// ============================================================================
// Determinism Tests
// ============================================================================

#[test]
fn test_different_encryptions_produce_different_output() {
    let input = create_temp_file("determinism_input.txt", b"Same input data");
    let encrypted1 = create_temp_file("determinism_encrypted1.bin", b"");
    let encrypted2 = create_temp_file("determinism_encrypted2.bin", b"");

    run_cascade_ok(&["-A", "-i", input.to_str().unwrap(), "-o", encrypted1.to_str().unwrap(), "-k", "testpass", "-s"]);
    run_cascade_ok(&["-A", "-i", input.to_str().unwrap(), "-o", encrypted2.to_str().unwrap(), "-k", "testpass", "-s"]);

    // Due to random nonces/IVs, encryptions should differ
    assert_ne!(fs::read(&encrypted1).unwrap(), fs::read(&encrypted2).unwrap(), "Encryptions should be non-deterministic");

    cleanup(&[input, encrypted1, encrypted2]);
}

// ============================================================================
// Progress Bar Test (just verify it doesn't crash)
// ============================================================================

#[test]
fn test_progress_flag_works() {
    let input = create_temp_file("progress_input.txt", b"Progress bar test");
    let encrypted = create_temp_file("progress_encrypted.bin", b"");
    let decrypted = create_temp_file("progress_decrypted.txt", b"");

    // Run with --progress flag
    run_cascade_ok(&["-A", "-S", "--progress", "-i", input.to_str().unwrap(), "-o", encrypted.to_str().unwrap(), "-k", "testpass"]);
    run_cascade_ok(&["-d", "--progress", "-i", encrypted.to_str().unwrap(), "-o", decrypted.to_str().unwrap(), "-k", "testpass"]);

    assert_eq!(fs::read(&input).unwrap(), fs::read(&decrypted).unwrap());

    cleanup(&[input, encrypted, decrypted]);
}
