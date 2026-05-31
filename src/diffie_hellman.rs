use num_bigint::{BigUint, RandBigInt, ToBigUint};
use num_traits::One;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// Diffie-Hellman key exchange parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhParams {
    pub p: String, // prime modulus (hex)
    pub g: String, // generator (hex)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhKeyPair {
    pub params: DhParams,
    pub private_key: String, // hex
    pub public_key: String,  // hex
}

/// Diffie-Hellman key exchange implementation
#[derive(Debug, Clone)]
pub struct DiffieHellman {
    params: DhParams,
    p: BigUint,
    g: BigUint,
    private_key: BigUint,
    public_key: BigUint,
}

impl DiffieHellman {
    /// Create a new DH instance with well-known or generated parameters
    pub fn new(bit_size: usize) -> Self {
        let p = Self::generate_safe_prime(bit_size);
        let g = 2u32.to_biguint().unwrap();
        let private_key = Self::generate_private_key(&p);
        let public_key = g.modpow(&private_key, &p);

        let params = DhParams {
            p: format!("{:x}", p),
            g: format!("{:x}", g),
        };

        DiffieHellman {
            params,
            p,
            g,
            private_key,
            public_key,
        }
    }

    pub fn public_key(&self) -> &BigUint {
        &self.public_key
    }

    pub fn params(&self) -> &DhParams {
        &self.params
    }

    /// Compute the shared secret given the other party's public key
    pub fn compute_shared_secret(&self, other_public: &BigUint) -> BigUint {
        other_public.modpow(&self.private_key, &self.p)
    }

    fn generate_private_key(p: &BigUint) -> BigUint {
        let mut rng = OsRng;
        let two = 2u32.to_biguint().unwrap();
        rng.gen_biguint_range(&two, &(p - BigUint::one()))
    }

    fn generate_safe_prime(bits: usize) -> BigUint {
        let mut rng = OsRng;
        loop {
            let q = rng.gen_biguint((bits - 1) as u64);
            let candidate = &q * 2u32 + BigUint::one();
            if candidate.bits() >= bits as u64 - 2
                && crate::rsa::Rsa::is_probably_prime(&candidate)
            {
                return candidate;
            }
        }
    }
}

// Primality test is in crate::rsa::Rsa::is_probably_prime (pub(crate))

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dh_shared_secret() {
        let alice = DiffieHellman::new(256);
        let _bob = DiffieHellman::new(256);

        // Alice and Bob need same params — create Bob with Alice's params
        let p = BigUint::parse_bytes(alice.params.p.as_bytes(), 16).unwrap();
        let g = BigUint::parse_bytes(alice.params.g.as_bytes(), 16).unwrap();

        let mut rng = OsRng;
        let two = 2u32.to_biguint().unwrap();
        let bob_private = rng.gen_biguint_range(&two, &(&p - BigUint::one()));
        let bob_public = g.modpow(&bob_private, &p);

        let shared_a = alice.compute_shared_secret(&bob_public);
        let shared_b = bob_public.modpow(&alice.private_key, &p);

        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn test_dh_different_public_keys() {
        let alice = DiffieHellman::new(256);
        let p = BigUint::parse_bytes(alice.params.p.as_bytes(), 16).unwrap();
        let g = BigUint::parse_bytes(alice.params.g.as_bytes(), 16).unwrap();

        let mut rng = OsRng;
        let two = 2u32.to_biguint().unwrap();
        let bob_private = rng.gen_biguint_range(&two, &(&p - BigUint::one()));
        let bob_public = g.modpow(&bob_private, &p);

        assert_ne!(bob_public, *alice.public_key());
    }

    #[test]
    fn test_dh_modular_exponentiation() {
        let p = BigUint::parse_bytes(b"17", 10).unwrap();
        let g = BigUint::parse_bytes(b"3", 10).unwrap();
        let priv_key = BigUint::parse_bytes(b"15", 10).unwrap();
        let pub_key = g.modpow(&priv_key, &p);
        // 3^15 mod 17 = 14348907 mod 17 = 6
        assert_eq!(pub_key, BigUint::parse_bytes(b"6", 10).unwrap());
    }

    #[test]
    fn test_dh_params_serialization() {
        let dh = DiffieHellman::new(256);
        let json = serde_json::to_string(dh.params()).unwrap();
        let params: DhParams = serde_json::from_str(&json).unwrap();
        assert_eq!(params.p, dh.params().p);
    }

    #[test]
    fn test_dh_commutativity() {
        // g^(a*b) mod p == g^(b*a) mod p
        let dh = DiffieHellman::new(256);
        let p = BigUint::parse_bytes(dh.params.p.as_bytes(), 16).unwrap();

        let mut rng = OsRng;
        let two = 2u32.to_biguint().unwrap();
        let a = rng.gen_biguint_range(&two, &(&p - BigUint::one()));
        let b = rng.gen_biguint_range(&two, &(&p - BigUint::one()));
        let g = BigUint::parse_bytes(dh.params.g.as_bytes(), 16).unwrap();

        let gab = g.modpow(&(&a * &b), &p);
        let gba = g.modpow(&(&b * &a), &p);
        assert_eq!(gab, gba);
    }
}
