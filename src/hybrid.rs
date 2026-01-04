//! Hybrid X25519 + Kyber1024 asymmetric encryption for header protection
//!
//! This module provides post-quantum secure encryption by combining:
//! - X25519: Fast elliptic curve Diffie-Hellman (classical security)
//! - Kyber1024: NIST-selected post-quantum KEM (quantum resistance)
//!
//! Both shared secrets are combined via HKDF to derive a symmetric key.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public, StaticSecret};
use zeroize::Zeroizing;

#[derive(Error, Debug)]
pub enum HybridError {
    #[error("Key generation failed")]
    KeyGeneration,
    #[error("Encryption failed: {0}")]
    Encryption(String),
    #[error("Decryption failed: {0}")]
    Decryption(String),
    #[error("Invalid public key format")]
    InvalidPublicKey,
    #[error("Invalid private key format")]
    InvalidPrivateKey,
    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Combined public key (X25519 + Kyber1024)
#[derive(Serialize, Deserialize, Clone)]
pub struct HybridPublicKey {
    pub x25519: [u8; 32],
    pub kyber: Vec<u8>,
}

/// Combined private key (X25519 + Kyber1024)
#[derive(Serialize, Deserialize)]
pub struct HybridPrivateKey {
    pub x25519: [u8; 32],
    pub kyber: Vec<u8>,
}

/// Keypair containing both public and private keys
#[derive(Serialize, Deserialize)]
pub struct HybridKeypair {
    pub public: HybridPublicKey,
    pub private: HybridPrivateKey,
}

/// Encapsulated keys (ephemeral public keys + ciphertexts)
#[derive(Serialize, Deserialize, Clone)]
pub struct EncapsulatedKeys {
    pub x25519_ephemeral: [u8; 32],
    pub kyber_ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
}

macro_rules! impl_json_serde {
    ($($t:ty),+) => {$(
        impl $t {
            pub fn to_json(&self) -> Result<String, HybridError> {
                serde_json::to_string_pretty(self).map_err(|e| HybridError::Serialization(e.to_string()))
            }
            pub fn from_json(json: &str) -> Result<Self, HybridError> {
                serde_json::from_str(json).map_err(|e| HybridError::Serialization(e.to_string()))
            }
        }
    )+};
}

impl_json_serde!(HybridKeypair, HybridPublicKey, HybridPrivateKey);

impl HybridKeypair {
    pub fn generate() -> Self {
        let x25519_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let x25519_public = X25519Public::from(&x25519_secret);
        let (kyber_pk, kyber_sk) = kyber1024::keypair();
        HybridKeypair {
            public: HybridPublicKey { x25519: x25519_public.to_bytes(), kyber: kyber_pk.as_bytes().to_vec() },
            private: HybridPrivateKey { x25519: *x25519_secret.as_bytes(), kyber: kyber_sk.as_bytes().to_vec() },
        }
    }
}

/// Derive a symmetric key from X25519 and Kyber shared secrets
fn derive_symmetric_key(x25519_shared: &[u8], kyber_shared: &[u8]) -> Zeroizing<[u8; 32]> {
    // Combine both shared secrets
    let mut combined = Zeroizing::new(Vec::with_capacity(x25519_shared.len() + kyber_shared.len()));
    combined.extend_from_slice(x25519_shared);
    combined.extend_from_slice(kyber_shared);

    // Use HKDF to derive final key
    let hk = Hkdf::<Sha256>::new(Some(b"cascade-crypt-hybrid"), &combined);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(b"header-encryption", key.as_mut())
        .expect("32 bytes is valid for HKDF");
    key
}

/// Encrypt data using hybrid X25519 + Kyber1024
pub fn encrypt(plaintext: &[u8], recipient_public: &HybridPublicKey) -> Result<(EncapsulatedKeys, Vec<u8>), HybridError> {
    // Generate ephemeral X25519 keypair
    let x25519_ephemeral = EphemeralSecret::random_from_rng(rand::thread_rng());
    let x25519_ephemeral_public = X25519Public::from(&x25519_ephemeral);

    // Perform X25519 key exchange
    let recipient_x25519 = X25519Public::from(recipient_public.x25519);
    let x25519_shared = x25519_ephemeral.diffie_hellman(&recipient_x25519);

    // Perform Kyber encapsulation
    let kyber_pk = kyber1024::PublicKey::from_bytes(&recipient_public.kyber)
        .map_err(|_| HybridError::InvalidPublicKey)?;
    let (kyber_shared, kyber_ciphertext) = kyber1024::encapsulate(&kyber_pk);

    // Derive symmetric key from both shared secrets
    let symmetric_key = derive_symmetric_key(x25519_shared.as_bytes(), kyber_shared.as_bytes());

    // Generate nonce
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt plaintext with ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(symmetric_key.as_slice())
        .map_err(|e| HybridError::Encryption(e.to_string()))?;
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| HybridError::Encryption(e.to_string()))?;

    let encapsulated = EncapsulatedKeys {
        x25519_ephemeral: x25519_ephemeral_public.to_bytes(),
        kyber_ciphertext: kyber_ciphertext.as_bytes().to_vec(),
        nonce: nonce_bytes,
    };

    Ok((encapsulated, ciphertext))
}

/// Decrypt data using hybrid X25519 + Kyber1024
pub fn decrypt(
    encapsulated: &EncapsulatedKeys,
    ciphertext: &[u8],
    private_key: &HybridPrivateKey,
) -> Result<Vec<u8>, HybridError> {
    // Perform X25519 key exchange
    let x25519_secret = StaticSecret::from(private_key.x25519);
    let x25519_ephemeral_public = X25519Public::from(encapsulated.x25519_ephemeral);
    let x25519_shared = x25519_secret.diffie_hellman(&x25519_ephemeral_public);

    // Perform Kyber decapsulation
    let kyber_sk = kyber1024::SecretKey::from_bytes(&private_key.kyber)
        .map_err(|_| HybridError::InvalidPrivateKey)?;
    let kyber_ct = kyber1024::Ciphertext::from_bytes(&encapsulated.kyber_ciphertext)
        .map_err(|_| HybridError::Decryption("Invalid Kyber ciphertext".into()))?;
    let kyber_shared = kyber1024::decapsulate(&kyber_ct, &kyber_sk);

    // Derive symmetric key from both shared secrets
    let symmetric_key = derive_symmetric_key(x25519_shared.as_bytes(), kyber_shared.as_bytes());

    // Decrypt with ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(symmetric_key.as_slice())
        .map_err(|e| HybridError::Decryption(e.to_string()))?;
    let nonce = Nonce::from_slice(&encapsulated.nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| HybridError::Decryption(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = HybridKeypair::generate();
        assert_eq!(keypair.public.x25519.len(), 32);
        assert!(!keypair.public.kyber.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let keypair = HybridKeypair::generate();
        let plaintext = b"Secret algorithm order: ATWS";

        let (encapsulated, ciphertext) = encrypt(plaintext, &keypair.public).unwrap();
        let decrypted = decrypt(&encapsulated, &ciphertext, &keypair.private).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_keypair_serialization() {
        let keypair = HybridKeypair::generate();
        let json = keypair.to_json().unwrap();
        let restored = HybridKeypair::from_json(&json).unwrap();

        assert_eq!(keypair.public.x25519, restored.public.x25519);
        assert_eq!(keypair.public.kyber, restored.public.kyber);
    }

    #[test]
    fn test_wrong_private_key_fails() {
        let keypair1 = HybridKeypair::generate();
        let keypair2 = HybridKeypair::generate();
        let plaintext = b"Secret data";

        let (encapsulated, ciphertext) = encrypt(plaintext, &keypair1.public).unwrap();
        let result = decrypt(&encapsulated, &ciphertext, &keypair2.private);

        assert!(result.is_err());
    }
}
