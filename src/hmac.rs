use crate::hash::Sha256Like;
use serde::{Deserialize, Serialize};

/// HMAC (Hash-based Message Authentication Code) implementation
#[derive(Debug, Clone)]
pub struct Hmac {
    key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HmacResult {
    pub code: Vec<u8>,
    pub hex: String,
}

impl Hmac {
    pub fn new(key: &[u8]) -> Self {
        Hmac { key: key.to_vec() }
    }

    /// Compute HMAC using the SHA-256-like hash
    /// HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
    pub fn compute(&self, message: &[u8]) -> HmacResult {
        let block_size = 64; // SHA-256 block size

        // Step 1: If key > block_size, hash it
        let key_prime = if self.key.len() > block_size {
            Sha256Like::digest(&self.key)
        } else {
            self.key.clone()
        };

        // Step 2: Pad key to block_size
        let mut padded_key = key_prime.clone();
        padded_key.resize(block_size, 0x00);

        // Step 3: Create ipad and opad
        let ipad: Vec<u8> = padded_key.iter().map(|b| b ^ 0x36).collect();
        let opad: Vec<u8> = padded_key.iter().map(|b| b ^ 0x5C).collect();

        // Step 4: Inner hash: H(ipad || message)
        let mut inner = Sha256Like::new();
        inner.update(&ipad);
        inner.update(message);
        let inner_hash = inner.finalize();

        // Step 5: Outer hash: H(opad || inner_hash)
        let mut outer = Sha256Like::new();
        outer.update(&opad);
        outer.update(&inner_hash);
        let result = outer.finalize();

        let hex = result.iter().map(|b| format!("{:02x}", b)).collect();
        HmacResult { code: result, hex }
    }

    /// Verify an HMAC
    pub fn verify(&self, message: &[u8], expected: &[u8]) -> bool {
        let computed = self.compute(message);
        // Constant-time comparison (simplified)
        if computed.code.len() != expected.len() {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in computed.code.iter().zip(expected.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_deterministic() {
        let hmac1 = Hmac::new(b"secret_key");
        let hmac2 = Hmac::new(b"secret_key");
        let r1 = hmac1.compute(b"message");
        let r2 = hmac2.compute(b"message");
        assert_eq!(r1.code, r2.code);
    }

    #[test]
    fn test_hmac_different_keys() {
        let h1 = Hmac::new(b"key1");
        let h2 = Hmac::new(b"key2");
        let r1 = h1.compute(b"same message");
        let r2 = h2.compute(b"same message");
        assert_ne!(r1.code, r2.code);
    }

    #[test]
    fn test_hmac_different_messages() {
        let hmac = Hmac::new(b"key");
        let r1 = hmac.compute(b"message1");
        let r2 = hmac.compute(b"message2");
        assert_ne!(r1.code, r2.code);
    }

    #[test]
    fn test_hmac_verify_correct() {
        let hmac = Hmac::new(b"secret");
        let result = hmac.compute(b"message");
        assert!(hmac.verify(b"message", &result.code));
    }

    #[test]
    fn test_hmac_verify_wrong_message() {
        let hmac = Hmac::new(b"secret");
        let result = hmac.compute(b"message");
        assert!(!hmac.verify(b"wrong message", &result.code));
    }

    #[test]
    fn test_hmac_verify_wrong_key() {
        let h1 = Hmac::new(b"secret1");
        let result = h1.compute(b"message");
        let h2 = Hmac::new(b"secret2");
        assert!(!h2.verify(b"message", &result.code));
    }

    #[test]
    fn test_hmac_long_key() {
        let long_key = vec![0xABu8; 200]; // longer than block size
        let hmac = Hmac::new(&long_key);
        let result = hmac.compute(b"test");
        assert_eq!(result.code.len(), 32);
    }

    #[test]
    fn test_hmac_empty_message() {
        let hmac = Hmac::new(b"key");
        let result = hmac.compute(b"");
        assert_eq!(result.code.len(), 32);
    }

    #[test]
    fn test_hmac_result_hex() {
        let hmac = Hmac::new(b"key");
        let result = hmac.compute(b"test");
        assert_eq!(result.hex.len(), 64);
    }
}
