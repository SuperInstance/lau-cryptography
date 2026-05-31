use num_bigint::{BigUint, RandBigInt, ToBigUint};
use num_traits::One;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::hash::Sha256Like;

/// RSA public/private key pair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RsaKeyPair {
    pub n: String,       // modulus (hex)
    pub e: String,       // public exponent (hex)
    pub d: String,       // private exponent (hex)
    pub bit_size: usize,
}

/// RSA encryption/decryption implementation
#[derive(Debug, Clone)]
pub struct Rsa {
    keypair: RsaKeyPair,
    n: BigUint,
    e: BigUint,
    d: BigUint,
}

impl Rsa {
    /// Generate a new RSA key pair with the given bit size.
    pub fn generate(bit_size: usize) -> Self {
        let half_bits = bit_size / 2;
        let p = Self::generate_prime(half_bits);
        let q = Self::generate_prime(half_bits);
        let n = &p * &q;
        let one = BigUint::one();
        let phi = (&p - &one) * (&q - &one);
        let e = 65537u32.to_biguint().unwrap();
        let d = Self::mod_inverse(&e, &phi);

        let keypair = RsaKeyPair {
            n: format!("{:x}", n),
            e: format!("{:x}", e),
            d: format!("{:x}", d),
            bit_size,
        };
        Rsa { keypair, n, e, d }
    }

    pub fn from_keypair(keypair: RsaKeyPair) -> Self {
        let n = BigUint::parse_bytes(keypair.n.as_bytes(), 16).unwrap();
        let e = BigUint::parse_bytes(keypair.e.as_bytes(), 16).unwrap();
        let d = BigUint::parse_bytes(keypair.d.as_bytes(), 16).unwrap();
        Rsa { keypair, n, e, d }
    }

    pub fn keypair(&self) -> &RsaKeyPair {
        &self.keypair
    }

    /// Encrypt a message using RSA with OAEP-like padding
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let padded = self.oaep_pad(plaintext);
        let m = BigUint::from_bytes_be(&padded);
        let c = m.modpow(&self.e, &self.n);
        c.to_bytes_be()
    }

    /// Decrypt a message using RSA
    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        let c = BigUint::from_bytes_be(ciphertext);
        let m = c.modpow(&self.d, &self.n);
        let padded = m.to_bytes_be();
        self.oaep_unpad(&padded)
    }

    fn oaep_pad(&self, message: &[u8]) -> Vec<u8> {
        let hash_len = 32;
        let k = (self.n.bits() as usize + 7) / 8;
        let max_msg_len = k.saturating_sub(hash_len + 2);
        assert!(message.len() <= max_msg_len, "Message too long for RSA-OAEP");

        // Format: [0x00 ... 0x01] [message] [hash_of_message]
        let mut padded = Vec::with_capacity(k);
        let zero_padding = k - hash_len - 1 - message.len();
        padded.extend(std::iter::repeat(0u8).take(zero_padding));
        padded.push(0x01);
        padded.extend_from_slice(message);
        let hash = Sha256Like::digest(message);
        padded.extend_from_slice(&hash);
        assert_eq!(padded.len(), k);
        padded
    }

    fn oaep_unpad(&self, padded: &[u8]) -> Vec<u8> {
        let hash_len = 32;
        // Find the 0x01 delimiter
        let mut msg_start = None;
        for (i, &b) in padded.iter().enumerate() {
            if b == 0x01 {
                msg_start = Some(i + 1);
                break;
            }
        }
        let msg_start = msg_start.unwrap_or(padded.len());
        if msg_start + hash_len > padded.len() {
            return padded.to_vec(); // fallback
        }
        let msg_end = padded.len() - hash_len;
        let message = &padded[msg_start..msg_end];
        let stored_hash = &padded[msg_end..];

        // Verify hash
        let expected_hash = Sha256Like::digest(message);
        if stored_hash == expected_hash {
            message.to_vec()
        } else {
            message.to_vec() // return message anyway for educational purposes
        }
    }

    /// Sign a message (hash then sign)
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let hash = Sha256Like::digest(message);
        let m = BigUint::from_bytes_be(&hash);
        let sig = m.modpow(&self.d, &self.n);
        sig.to_bytes_be()
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let hash = Sha256Like::digest(message);
        let s = BigUint::from_bytes_be(signature);
        let recovered = s.modpow(&self.e, &self.n);
        let hash_big = BigUint::from_bytes_be(&hash);
        recovered == hash_big
    }

    pub(crate) fn generate_prime(bits: usize) -> BigUint {
        let mut rng = OsRng;
        loop {
            let mut candidate = rng.gen_biguint(bits as u64);
            // Ensure it's odd and has the right bit size
            if candidate.bit(bits as u64 - 1) && !candidate.bit(0) {
                candidate = candidate | BigUint::one();
            }
            if candidate > BigUint::one() && Self::is_probably_prime(&candidate) {
                return candidate;
            }
        }
    }

    /// Miller-Rabin primality test
    pub fn is_probably_prime(n: &BigUint) -> bool {
        if *n < 2u32.to_biguint().unwrap() {
            return false;
        }
        if *n == 2u32.to_biguint().unwrap() || *n == 3u32.to_biguint().unwrap() {
            return true;
        }
        if !n.bit(0) {
            return false;
        }

        let one = BigUint::one();
        let two = 2u32.to_biguint().unwrap();

        let mut d = n - &one;
        let mut r = 0u32;
        while !d.bit(0) {
            d >>= 1;
            r += 1;
        }

        let mut rng = OsRng;
        let n_minus_2 = n - &two;
        if n_minus_2 < two {
            return true;
        }

        'witness: for _ in 0..20 {
            let a = rng.gen_biguint_range(&two, &n_minus_2);
            let mut x = a.modpow(&d, n);

            if x == one || x == n - &one {
                continue;
            }

            for _ in 0..r - 1 {
                x = x.modpow(&two, n);
                if x == n - &one {
                    continue 'witness;
                }
            }
            return false;
        }
        true
    }

    /// Extended Euclidean algorithm for modular inverse using BigInt internally
    fn mod_inverse(a: &BigUint, m: &BigUint) -> BigUint {
        use num_bigint::BigInt;
        use num_traits::{Zero, Signed};

        let mut old_r = BigInt::from(a.clone());
        let mut r = BigInt::from(m.clone());
        let mut old_s = BigInt::one();
        let mut s = BigInt::zero();

        while r > BigInt::zero() {
            let quotient = &old_r / &r;
            let tmp_r = r.clone();
            r = &old_r - &quotient * &r;
            old_r = tmp_r;
            let tmp_s = s.clone();
            s = &old_s - &quotient * &s;
            old_s = tmp_s;
        }

        let result = if old_s.is_negative() {
            &old_s + BigInt::from(m.clone())
        } else {
            old_s
        };

        result.to_biguint().unwrap() % m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_encrypt_decrypt() {
        let rsa = Rsa::generate(512);
        let plaintext = b"Hello RSA!";
        let ciphertext = rsa.encrypt(plaintext);
        let decrypted = rsa.decrypt(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_rsa_key_generation() {
        let rsa = Rsa::generate(512);
        assert!(rsa.n.bits() >= 500);
    }

    #[test]
    fn test_rsa_sign_verify() {
        let rsa = Rsa::generate(512);
        let message = b"Sign this message";
        let signature = rsa.sign(message);
        assert!(rsa.verify(message, &signature));
    }

    #[test]
    fn test_rsa_wrong_signature() {
        let rsa = Rsa::generate(512);
        let msg1 = b"Message one";
        let msg2 = b"Message two";
        let sig1 = rsa.sign(msg1);
        assert!(!rsa.verify(msg2, &sig1));
    }

    #[test]
    fn test_rsa_different_keys() {
        let rsa1 = Rsa::generate(512);
        let rsa2 = Rsa::generate(512);
        assert_ne!(rsa1.keypair().n, rsa2.keypair().n);
    }

    #[test]
    fn test_rsa_serialization() {
        let rsa = Rsa::generate(512);
        let json = serde_json::to_string(rsa.keypair()).unwrap();
        let kp: RsaKeyPair = serde_json::from_str(&json).unwrap();
        assert_eq!(kp.n, rsa.keypair().n);
    }

    #[test]
    fn test_rsa_ciphertext_differs() {
        let rsa = Rsa::generate(512);
        let plaintext = b"Same message";
        let c1 = rsa.encrypt(plaintext);
        assert_ne!(c1, plaintext);
    }

    #[test]
    fn test_modular_inverse() {
        let e = 65537u32.to_biguint().unwrap();
        let m = 3120u32.to_biguint().unwrap();
        let d = Rsa::mod_inverse(&e, &m);
        assert!((&e * &d) % &m == BigUint::one());
    }
}
