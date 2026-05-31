use num_bigint::{BigUint, RandBigInt, ToBigUint};
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::hash::Sha256Like;

/// Schnorr zero-knowledge proof protocol
/// Proves knowledge of a discrete logarithm without revealing it.
///
/// Protocol:
/// 1. Prover picks random r, sends R = g^r
/// 2. Verifier sends challenge c = H(g, y, R)
/// 3. Prover computes s = r + c*x mod n
/// 4. Verifier checks: g^s == R * y^c
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchnorrCommitment {
    pub r_point: String, // g^r (hex)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchnorrChallenge {
    pub challenge: String, // c (hex)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchnorrResponse {
    pub response: String, // s = r + c*x mod n (hex)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchnorrProof {
    pub commitment: SchnorrCommitment,
    pub challenge: SchnorrChallenge,
    pub response: SchnorrResponse,
    pub public_key: String, // y = g^x (hex)
    pub generator: String,  // g (hex)
    pub modulus: String,    // p (hex)
    pub order: String,      // n (hex)
}

pub struct SchnorrZKP {
    p: BigUint, // modulus
    g: BigUint, // generator
    n: BigUint, // order
}

impl SchnorrZKP {
    pub fn new(p: BigUint, g: BigUint, n: BigUint) -> Self {
        SchnorrZKP { p, g, n }
    }

    /// Create a proof of knowledge of the discrete log of y = g^x
    pub fn prove(&self, x: &BigUint) -> SchnorrProof {
        let mut rng = OsRng;

        // Step 1: Pick random r
        let r = rng.gen_biguint_below(&self.n);

        // Compute R = g^r mod p
        let r_point = self.g.modpow(&r, &self.p);

        // Compute public key y = g^x mod p
        let y = self.g.modpow(x, &self.p);

        // Step 2: Compute challenge c = H(g, y, R)
        let c = self.compute_challenge(&self.g, &y, &r_point);

        // Step 3: Compute s = r + c*x mod n
        let s = (&r + &c * x) % &self.n;

        SchnorrProof {
            commitment: SchnorrCommitment {
                r_point: format!("{:x}", r_point),
            },
            challenge: SchnorrChallenge {
                challenge: format!("{:x}", c),
            },
            response: SchnorrResponse {
                response: format!("{:x}", s),
            },
            public_key: format!("{:x}", y),
            generator: format!("{:x}", self.g),
            modulus: format!("{:x}", self.p),
            order: format!("{:x}", self.n),
        }
    }

    /// Verify a Schnorr proof
    pub fn verify(&self, proof: &SchnorrProof) -> bool {
        let r_point = BigUint::parse_bytes(proof.commitment.r_point.as_bytes(), 16).unwrap();
        let c = BigUint::parse_bytes(proof.challenge.challenge.as_bytes(), 16).unwrap();
        let s = BigUint::parse_bytes(proof.response.response.as_bytes(), 16).unwrap();
        let y = BigUint::parse_bytes(proof.public_key.as_bytes(), 16).unwrap();

        // Verify challenge
        let expected_c = self.compute_challenge(&self.g, &y, &r_point);
        if c != expected_c {
            return false;
        }

        // Verify: g^s mod p == R * y^c mod p
        let lhs = self.g.modpow(&s, &self.p);
        let y_c = y.modpow(&c, &self.p);
        let rhs = (&r_point * &y_c) % &self.p;

        lhs == rhs
    }

    fn compute_challenge(&self, g: &BigUint, y: &BigUint, r: &BigUint) -> BigUint {
        let mut hasher = Sha256Like::new();
        hasher.update(&g.to_bytes_be());
        hasher.update(&y.to_bytes_be());
        hasher.update(&r.to_bytes_be());
        let hash = hasher.finalize();
        // Take first 32 bytes and interpret as BigUint, then mod n
        let hash_int = BigUint::from_bytes_be(&hash);
        hash_int % &self.n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_zkp() -> (SchnorrZKP, BigUint) {
        // Use a small safe prime for testing
        let p = BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
            16,
        ).unwrap();
        let g = BigUint::from(2u32);
        let n = &p - BigUint::one();
        let zkp = SchnorrZKP::new(p, g, n);

        let secret = BigUint::from(12345u32);
        (zkp, secret)
    }

    #[test]
    fn test_schnorr_proof_completeness() {
        let (zkp, secret) = setup_zkp();
        let proof = zkp.prove(&secret);
        assert!(zkp.verify(&proof));
    }

    #[test]
    fn test_schnorr_tampered_response() {
        let (zkp, secret) = setup_zkp();
        let mut proof = zkp.prove(&secret);
        // Tamper with the response
        proof.response.response = format!("{:x}", BigUint::from(99999u32));
        assert!(!zkp.verify(&proof));
    }

    #[test]
    fn test_schnorr_tampered_commitment() {
        let (zkp, secret) = setup_zkp();
        let mut proof = zkp.prove(&secret);
        proof.commitment.r_point = format!("{:x}", BigUint::from(12345u32));
        assert!(!zkp.verify(&proof));
    }

    #[test]
    fn test_schnorr_different_secrets() {
        let (zkp, _) = setup_zkp();
        let proof1 = zkp.prove(&BigUint::from(111u32));
        let proof2 = zkp.prove(&BigUint::from(222u32));
        // Different secrets produce different proofs
        assert_ne!(proof1.public_key, proof2.public_key);
        assert!(zkp.verify(&proof1));
        assert!(zkp.verify(&proof2));
    }

    #[test]
    fn test_schnorr_serialization() {
        let (zkp, secret) = setup_zkp();
        let proof = zkp.prove(&secret);
        let json = serde_json::to_string(&proof).unwrap();
        let deserialized: SchnorrProof = serde_json::from_str(&json).unwrap();
        assert!(zkp.verify(&deserialized));
    }

    #[test]
    fn test_schnorr_non_interactive() {
        // Fiat-Shamir: challenge is derived from hash, making it non-interactive
        let (zkp, secret) = setup_zkp();
        let proof = zkp.prove(&secret);
        // Anyone can verify without interaction
        assert!(zkp.verify(&proof));
    }
}
