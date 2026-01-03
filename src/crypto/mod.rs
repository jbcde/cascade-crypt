pub mod aes256;
pub mod aria_cipher;
pub mod blowfish_cipher;
pub mod camellia;
pub mod cast5_cipher;
pub mod chacha;
pub mod idea_cipher;
pub mod kuznyechik_cipher;
pub mod serpent;
pub mod sm4_cipher;
pub mod tripledes;
pub mod twofish;
pub mod xchacha;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
    #[error("Invalid nonce/IV")]
    InvalidNonce,
}

/// Algorithm short codes for header
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    // Original algorithms
    Aes256,           // 'A'
    TripleDes,        // 'T'
    Twofish,          // 'W'
    Serpent,          // 'S'
    // Stream ciphers
    ChaCha20Poly1305, // 'C'
    XChaCha20Poly1305, // 'X'
    // Additional block ciphers
    Camellia,         // 'M'
    Blowfish,         // 'B'
    Cast5,            // 'F' (Five)
    Idea,             // 'I'
    Aria,             // 'R'
    Sm4,              // '4'
    Kuznyechik,       // 'K'
}

impl Algorithm {
    pub fn code(&self) -> char {
        match self {
            Algorithm::Aes256 => 'A',
            Algorithm::TripleDes => 'T',
            Algorithm::Twofish => 'W',
            Algorithm::Serpent => 'S',
            Algorithm::ChaCha20Poly1305 => 'C',
            Algorithm::XChaCha20Poly1305 => 'X',
            Algorithm::Camellia => 'M',
            Algorithm::Blowfish => 'B',
            Algorithm::Cast5 => 'F',
            Algorithm::Idea => 'I',
            Algorithm::Aria => 'R',
            Algorithm::Sm4 => '4',
            Algorithm::Kuznyechik => 'K',
        }
    }

    pub fn from_code(c: char) -> Option<Algorithm> {
        match c {
            'A' => Some(Algorithm::Aes256),
            'T' => Some(Algorithm::TripleDes),
            'W' => Some(Algorithm::Twofish),
            'S' => Some(Algorithm::Serpent),
            'C' => Some(Algorithm::ChaCha20Poly1305),
            'X' => Some(Algorithm::XChaCha20Poly1305),
            'M' => Some(Algorithm::Camellia),
            'B' => Some(Algorithm::Blowfish),
            'F' => Some(Algorithm::Cast5),
            'I' => Some(Algorithm::Idea),
            'R' => Some(Algorithm::Aria),
            '4' => Some(Algorithm::Sm4),
            'K' => Some(Algorithm::Kuznyechik),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Algorithm::Aes256 => "AES-256-GCM",
            Algorithm::TripleDes => "3DES-CBC",
            Algorithm::Twofish => "Twofish-256-CBC",
            Algorithm::Serpent => "Serpent-256-CBC",
            Algorithm::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            Algorithm::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            Algorithm::Camellia => "Camellia-256-CBC",
            Algorithm::Blowfish => "Blowfish-256-CBC",
            Algorithm::Cast5 => "CAST5-CBC",
            Algorithm::Idea => "IDEA-CBC",
            Algorithm::Aria => "ARIA-256-CBC",
            Algorithm::Sm4 => "SM4-CBC",
            Algorithm::Kuznyechik => "Kuznyechik-CBC",
        }
    }

    /// Key size in bytes for this algorithm
    pub fn key_size(&self) -> usize {
        match self {
            Algorithm::Aes256 => 32,
            Algorithm::TripleDes => 24,
            Algorithm::Twofish => 32,
            Algorithm::Serpent => 32,
            Algorithm::ChaCha20Poly1305 => 32,
            Algorithm::XChaCha20Poly1305 => 32,
            Algorithm::Camellia => 32,
            Algorithm::Blowfish => 32,
            Algorithm::Cast5 => 16,   // 128-bit
            Algorithm::Idea => 16,    // 128-bit
            Algorithm::Aria => 32,
            Algorithm::Sm4 => 16,     // 128-bit
            Algorithm::Kuznyechik => 32,
        }
    }

    /// Salt identifier for key derivation (unique per algorithm)
    pub fn salt_context(&self) -> &'static [u8] {
        match self {
            Algorithm::Aes256 => b"cascade-aes256",
            Algorithm::TripleDes => b"cascade-3des",
            Algorithm::Twofish => b"cascade-twofish",
            Algorithm::Serpent => b"cascade-serpent",
            Algorithm::ChaCha20Poly1305 => b"cascade-chacha20",
            Algorithm::XChaCha20Poly1305 => b"cascade-xchacha20",
            Algorithm::Camellia => b"cascade-camellia",
            Algorithm::Blowfish => b"cascade-blowfish",
            Algorithm::Cast5 => b"cascade-cast5",
            Algorithm::Idea => b"cascade-idea",
            Algorithm::Aria => b"cascade-aria",
            Algorithm::Sm4 => b"cascade-sm4",
            Algorithm::Kuznyechik => b"cascade-kuznyechik",
        }
    }
}

/// Trait for all encryption algorithms
pub trait Cipher {
    /// Encrypt data with the given key
    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Decrypt data with the given key
    fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Get the algorithm type
    fn algorithm(&self) -> Algorithm;
}

/// Create a cipher instance for the given algorithm
pub fn create_cipher(algo: Algorithm) -> Box<dyn Cipher> {
    match algo {
        Algorithm::Aes256 => Box::new(aes256::Aes256Cipher),
        Algorithm::TripleDes => Box::new(tripledes::TripleDesCipher),
        Algorithm::Twofish => Box::new(twofish::TwofishCipher),
        Algorithm::Serpent => Box::new(serpent::SerpentCipher),
        Algorithm::ChaCha20Poly1305 => Box::new(chacha::ChaCha20Poly1305Cipher),
        Algorithm::XChaCha20Poly1305 => Box::new(xchacha::XChaCha20Poly1305Cipher),
        Algorithm::Camellia => Box::new(camellia::CamelliaCipher),
        Algorithm::Blowfish => Box::new(blowfish_cipher::BlowfishCipher),
        Algorithm::Cast5 => Box::new(cast5_cipher::Cast5Cipher),
        Algorithm::Idea => Box::new(idea_cipher::IdeaCipher),
        Algorithm::Aria => Box::new(aria_cipher::AriaCipher),
        Algorithm::Sm4 => Box::new(sm4_cipher::Sm4Cipher),
        Algorithm::Kuznyechik => Box::new(kuznyechik_cipher::KuznyechikCipher),
    }
}
