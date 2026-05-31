use crate::hash::Sha256Like;
use crate::rsa::Rsa;
use serde::{Deserialize, Serialize};

/// RSA-based digital signature with SHA-256 hashing
#[derive(Debug, Clone)]
pub struct RsaSignature {
    rsa: Rsa,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessage {
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
    pub public_key_n: String,
    pub public_key_e: String,
}

impl RsaSignature {
    pub fn new(rsa: Rsa) -> Self {
        RsaSignature { rsa }
    }

    pub fn generate(bit_size: usize) -> Self {
        RsaSignature::new(Rsa::generate(bit_size))
    }

    /// Sign a message: hash it, then sign the hash
    pub fn sign(&self, message: &[u8]) -> SignedMessage {
        let signature = self.rsa.sign(message);
        let kp = self.rsa.keypair();
        SignedMessage {
            message: message.to_vec(),
            signature,
            public_key_n: kp.n.clone(),
            public_key_e: kp.e.clone(),
        }
    }

    /// Verify a signed message
    pub fn verify(&self, signed: &SignedMessage) -> bool {
        self.rsa.verify(&signed.message, &signed.signature)
    }

    /// Verify using just the public key info from a SignedMessage
    pub fn verify_with_public_key(signed: &SignedMessage) -> bool {
        use num_bigint::BigUint;
        use num_traits::One;

        let n = BigUint::parse_bytes(signed.public_key_n.as_bytes(), 16).unwrap();
        let e = BigUint::parse_bytes(signed.public_key_e.as_bytes(), 16).unwrap();

        let hash = Sha256Like::digest(&signed.message);
        let s = BigUint::from_bytes_be(&signed.signature);
        let recovered = s.modpow(&e, &n);
        let hash_big = BigUint::from_bytes_be(&hash);

        recovered == hash_big
    }

    pub fn rsa(&self) -> &Rsa {
        &self.rsa
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let sig_scheme = RsaSignature::generate(512);
        let signed = sig_scheme.sign(b"Test message for signing");
        assert!(sig_scheme.verify(&signed));
    }

    #[test]
    fn test_verify_with_public_key() {
        let sig_scheme = RsaSignature::generate(512);
        let signed = sig_scheme.sign(b"Public key verification test");
        assert!(RsaSignature::verify_with_public_key(&signed));
    }

    #[test]
    fn test_tampered_message() {
        let sig_scheme = RsaSignature::generate(512);
        let mut signed = sig_scheme.sign(b"Original message");
        signed.message[0] ^= 0xFF; // tamper
        assert!(!sig_scheme.verify(&signed));
    }

    #[test]
    fn test_different_messages() {
        let sig_scheme = RsaSignature::generate(512);
        let signed = sig_scheme.sign(b"Message A");
        // Try to verify with a different verifier
        let sig_scheme2 = RsaSignature::generate(512);
        assert!(!sig_scheme2.verify(&signed)); // Different key
    }

    #[test]
    fn test_signed_message_serialization() {
        let sig_scheme = RsaSignature::generate(512);
        let signed = sig_scheme.sign(b"Serialize test");
        let json = serde_json::to_string(&signed).unwrap();
        let deserialized: SignedMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.message, signed.message);
    }

    #[test]
    fn test_empty_message() {
        let sig_scheme = RsaSignature::generate(512);
        let signed = sig_scheme.sign(b"");
        assert!(sig_scheme.verify(&signed));
    }

    #[test]
    fn test_large_message() {
        let sig_scheme = RsaSignature::generate(512);
        let message = vec![0xABu8; 10000];
        let signed = sig_scheme.sign(&message);
        assert!(sig_scheme.verify(&signed));
    }
}
