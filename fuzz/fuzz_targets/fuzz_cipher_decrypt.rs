#![no_main]
use libfuzzer_sys::fuzz_target;
use cascrypt::crypto;
use cascrypt::Algorithm;

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

fuzz_target!(|data: &[u8]| {
    // Use first byte to select algorithm, rest is ciphertext
    if data.is_empty() {
        return;
    }
    let algo_idx = data[0] as usize % ALL_ALGORITHMS.len();
    let algo = ALL_ALGORITHMS[algo_idx];
    let ciphertext = &data[1..];

    // Use a fixed key of the correct size for each algorithm
    let key = vec![0x42u8; algo.key_size()];
    let _ = crypto::decrypt(algo, &key, ciphertext);
});
