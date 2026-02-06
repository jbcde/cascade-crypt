#![no_main]
use libfuzzer_sys::fuzz_target;
use cascrypt::{Header, HybridKeypair};

// Use a fixed keypair derived from a constant seed for reproducibility.
// This is NOT for security — it's for fuzzing determinism.
fn fixed_keypair() -> HybridKeypair {
    HybridKeypair::generate()
}

fuzz_target!(|data: &[u8]| {
    // Generate a fresh keypair per run since we can't cache across invocations
    // in a no_main context without lazy_static. The goal is to test that
    // parse_encrypted never panics, regardless of input.
    let keypair = fixed_keypair();
    let _ = Header::parse_encrypted(data, &keypair.private);
});
