use serde::{Deserialize, Serialize};

/// Merkle-Damgard based hash function with a SHA-like compression function.
/// This is a simplified educational implementation — not production-grade.
#[derive(Debug, Clone)]
pub struct Sha256Like {
    state: [u32; 8],
    count: u64,
    buffer: Vec<u8>,
}

// SHA-256 initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// Round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[inline]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline]
fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

#[inline]
fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

#[inline]
fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[inline]
fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

impl Sha256Like {
    pub fn new() -> Self {
        Sha256Like {
            state: H0,
            count: 0,
            buffer: Vec::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.count += data.len() as u64;
        self.buffer.extend_from_slice(data);

        while self.buffer.len() >= 64 {
            let block: [u8; 64] = self.buffer[..64].try_into().unwrap();
            self.compress(&block);
            self.buffer.drain(..64);
        }
    }

    pub fn finalize(mut self) -> Vec<u8> {
        // Padding
        let bit_len = self.count * 8;
        self.buffer.push(0x80);
        while self.buffer.len() % 64 != 56 {
            self.buffer.push(0x00);
        }
        self.buffer.extend_from_slice(&bit_len.to_be_bytes());

        while self.buffer.len() >= 64 {
            let block: [u8; 64] = self.buffer[..64].try_into().unwrap();
            self.compress(&block);
            self.buffer.drain(..64);
        }

        let mut result = Vec::with_capacity(32);
        for &word in &self.state {
            result.extend_from_slice(&word.to_be_bytes());
        }
        result
    }

    pub fn digest(data: &[u8]) -> Vec<u8> {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];

        // Parse block into 16 big-endian 32-bit words
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        // Extend to 64 words
        for i in 16..64 {
            w[i] = small_sigma1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(small_sigma0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        // Initialize working variables
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        // 64 rounds
        for i in 0..64 {
            let t1 = h
                .wrapping_add(big_sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        // Add compressed chunk to hash state
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

impl Default for Sha256Like {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashResult {
    pub bytes: Vec<u8>,
    pub hex: String,
}

impl HashResult {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let hex = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        HashResult { bytes, hex }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_hash() {
        let hash = Sha256Like::digest(&[]);
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_deterministic() {
        let h1 = Sha256Like::digest(b"hello");
        let h2 = Sha256Like::digest(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_collision_resistance() {
        let h1 = Sha256Like::digest(b"message1");
        let h2 = Sha256Like::digest(b"message2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_avalanche() {
        let h1 = Sha256Like::digest(b"hello");
        let h2 = Sha256Like::digest(b"hellp"); // one bit difference
        let diff_bits: u32 = h1.iter().zip(h2.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum();
        // Should have roughly 50% bit flip (~128 bits out of 256)
        assert!(diff_bits > 64, "Avalanche effect too weak: {} bits flipped", diff_bits);
    }

    #[test]
    fn test_incremental_update() {
        let mut h1 = Sha256Like::new();
        h1.update(b"hello world");

        let mut h2 = Sha256Like::new();
        h2.update(b"hello ");
        h2.update(b"world");

        assert_eq!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn test_hash_result_hex() {
        let hash = Sha256Like::digest(&[]);
        let result = HashResult::from_bytes(hash);
        assert_eq!(result.hex.len(), 64);
    }

    #[test]
    fn test_known_sha256_empty() {
        let hash = Sha256Like::digest(&[]);
        let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_known_sha256_abc() {
        let hash = Sha256Like::digest(b"abc");
        let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn test_large_input() {
        let data = vec![0xABu8; 1024 * 1024]; // 1 MB
        let hash = Sha256Like::digest(&data);
        assert_eq!(hash.len(), 32);
    }
}
