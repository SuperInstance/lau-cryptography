use serde::{Deserialize, Serialize};

const BLOCK_SIZE: usize = 16;

/// Feistel-network based block cipher (educational, not production-grade).
/// Feistel structure guarantees reversibility regardless of the round function.
#[derive(Debug, Clone)]
pub struct BlockCipher {
    round_keys: Vec<[u8; 16]>,
    rounds: usize,
}

impl BlockCipher {
    pub fn new(key: &[u8]) -> Self {
        let rounds = 16;
        let round_keys = Self::key_expansion(key, rounds);
        BlockCipher { round_keys, rounds }
    }

    fn key_expansion(key: &[u8], rounds: usize) -> Vec<[u8; 16]> {
        use crate::hash::Sha256Like;
        let mut keys = Vec::new();
        // Generate round keys by hashing iteratively
        let mut data = key.to_vec();
        for _ in 0..rounds + 1 {
            let hash = Sha256Like::digest(&data);
            let mut rk = [0u8; 16];
            rk.copy_from_slice(&hash[..16]);
            keys.push(rk);
            data = hash;
        }
        keys
    }

    /// Round function F(R_i, K_i) — doesn't need to be invertible for Feistel
    fn round_function(right: &[u8], key: &[u8; 16]) -> [u8; 8] {
        let mut out = [0u8; 8];
        for i in 0..8 {
            out[i] = right[i]
                .wrapping_add(key[i])
                .wrapping_mul(key[i + 8])
                .wrapping_add(right[(i + 3) % 8])
                ^ key[i + 4];
        }
        // Second pass for more mixing
        for i in 0..8 {
            out[i] = out[i].wrapping_add(out[(i + 5) % 8]).wrapping_mul(0x9E);
        }
        out
    }

    pub fn encrypt_block(&self, plaintext: &[u8; 16]) -> [u8; 16] {
        // Use a simple provably-reversible construction:
        // Split into L(8) and R(8), apply Luby-Rackoff-style Feistel
        let mut left = [0u8; 8];
        let mut right = [0u8; 8];
        left.copy_from_slice(&plaintext[..8]);
        right.copy_from_slice(&plaintext[8..]);

        for i in 0..self.rounds {
            let f_out = Self::round_function(&right, &self.round_keys[i]);
            let mut new_right = [0u8; 8];
            for j in 0..8 {
                new_right[j] = left[j] ^ f_out[j];
            }
            left = right;
            right = new_right;
        }

        let mut result = [0u8; 16];
        result[..8].copy_from_slice(&left);
        result[8..].copy_from_slice(&right);
        result
    }

    pub fn decrypt_block(&self, ciphertext: &[u8; 16]) -> [u8; 16] {
        let mut left = [0u8; 8];
        let mut right = [0u8; 8];
        left.copy_from_slice(&ciphertext[..8]);
        right.copy_from_slice(&ciphertext[8..]);

        for i in (0..self.rounds).rev() {
            // Inverse of encrypt step:
            // encrypt: left_new = right_old, right_new = left_old ^ F(right_old, K)
            // inverse: right_old = left_new, left_old = right_new ^ F(left_new, K)
            let f_out = Self::round_function(&left, &self.round_keys[i]);
            let mut new_left = [0u8; 8];
            for j in 0..8 {
                new_left[j] = right[j] ^ f_out[j];
            }
            right = left;
            left = new_left;
        }

        let mut result = [0u8; 16];
        result[..8].copy_from_slice(&left);
        result[8..].copy_from_slice(&right);
        result
    }

    pub fn block_size(&self) -> usize {
        BLOCK_SIZE
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModeOfOperation {
    ECB,
    CBC,
    CTR,
}

fn xor_blocks(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding_len = block_size - (data.len() % block_size);
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat(padding_len as u8).take(padding_len));
    padded
}

fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.is_empty() {
        return Err("Empty data".into());
    }
    let padding_len = *data.last().unwrap() as usize;
    if padding_len == 0 || padding_len > data.len() || padding_len > 16 {
        return Err("Invalid padding".into());
    }
    for &b in &data[data.len() - padding_len..] {
        if b != padding_len as u8 {
            return Err("Invalid padding".into());
        }
    }
    Ok(data[..data.len() - padding_len].to_vec())
}

pub fn encrypt(cipher: &BlockCipher, data: &[u8], mode: ModeOfOperation, iv: Option<&[u8]>) -> Vec<u8> {
    let padded = pkcs7_pad(data, BLOCK_SIZE);
    match mode {
        ModeOfOperation::ECB => {
            padded.chunks(BLOCK_SIZE).flat_map(|chunk| {
                let block: [u8; 16] = chunk.try_into().unwrap();
                cipher.encrypt_block(&block).to_vec()
            }).collect()
        }
        ModeOfOperation::CBC => {
            let iv = iv.unwrap();
            let mut prev = [0u8; 16];
            prev.copy_from_slice(&iv[..16]);
            padded.chunks(BLOCK_SIZE).flat_map(|chunk| {
                let xored: Vec<u8> = xor_blocks(chunk, &prev);
                let block: [u8; 16] = xored.try_into().unwrap();
                let encrypted = cipher.encrypt_block(&block);
                prev = encrypted;
                encrypted.to_vec()
            }).collect()
        }
        ModeOfOperation::CTR => {
            let mut counter = [0u8; 16];
            if let Some(iv_data) = iv {
                counter[..iv_data.len().min(16)].copy_from_slice(&iv_data[..iv_data.len().min(16)]);
            }
            let nonce = counter;
            let mut result = Vec::new();
            let mut ctr = 0u128;
            for chunk in padded.chunks(BLOCK_SIZE) {
                let mut ctr_block = nonce;
                let ctr_bytes = ctr.to_be_bytes();
                for i in 0..16 {
                    ctr_block[i] ^= ctr_bytes[i];
                }
                let keystream = cipher.encrypt_block(&ctr_block);
                let encrypted = xor_blocks(chunk, &keystream[..chunk.len()]);
                result.extend(encrypted);
                ctr += 1;
            }
            result
        }
    }
}

pub fn decrypt(cipher: &BlockCipher, data: &[u8], mode: ModeOfOperation, iv: Option<&[u8]>) -> Result<Vec<u8>, String> {
    if data.len() % BLOCK_SIZE != 0 {
        return Err("Ciphertext length must be multiple of block size".into());
    }
    let decrypted: Vec<u8> = match mode {
        ModeOfOperation::ECB => {
            data.chunks(BLOCK_SIZE).flat_map(|chunk| {
                let block: [u8; 16] = chunk.try_into().unwrap();
                cipher.decrypt_block(&block).to_vec()
            }).collect()
        }
        ModeOfOperation::CBC => {
            let iv = iv.unwrap();
            let mut prev = [0u8; 16];
            prev.copy_from_slice(&iv[..16]);
            data.chunks(BLOCK_SIZE).flat_map(|chunk| {
                let block: [u8; 16] = chunk.try_into().unwrap();
                let decrypted = cipher.decrypt_block(&block);
                let plaintext = xor_blocks(&decrypted, &prev);
                prev = block;
                plaintext
            }).collect()
        }
        ModeOfOperation::CTR => {
            let mut counter = [0u8; 16];
            if let Some(iv_data) = iv {
                counter[..iv_data.len().min(16)].copy_from_slice(&iv_data[..iv_data.len().min(16)]);
            }
            let nonce = counter;
            let mut result = Vec::new();
            let mut ctr = 0u128;
            for chunk in data.chunks(BLOCK_SIZE) {
                let mut ctr_block = nonce;
                let ctr_bytes = ctr.to_be_bytes();
                for i in 0..16 {
                    ctr_block[i] ^= ctr_bytes[i];
                }
                let keystream = cipher.encrypt_block(&ctr_block);
                let decrypted = xor_blocks(chunk, &keystream[..chunk.len()]);
                result.extend(decrypted);
                ctr += 1;
            }
            result
        }
    };
    pkcs7_unpad(&decrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cipher() -> BlockCipher {
        BlockCipher::new(b"testkey123456789")
    }

    #[test]
    fn test_block_cipher_roundtrip() {
        let cipher = make_cipher();
        let plaintext = b"Hello, World!!!!";
        let encrypted = cipher.encrypt_block(plaintext);
        let decrypted = cipher.decrypt_block(&encrypted);
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_ecb_roundtrip() {
        let cipher = make_cipher();
        let plaintext = b"Hello, ECB mode test data!";
        let encrypted = encrypt(&cipher, plaintext, ModeOfOperation::ECB, None);
        let decrypted = decrypt(&cipher, &encrypted, ModeOfOperation::ECB, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cbc_roundtrip() {
        let cipher = make_cipher();
        let iv = [0u8; 16];
        let plaintext = b"CBC mode encryption test!";
        let encrypted = encrypt(&cipher, plaintext, ModeOfOperation::CBC, Some(&iv));
        let decrypted = decrypt(&cipher, &encrypted, ModeOfOperation::CBC, Some(&iv)).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ctr_roundtrip() {
        let cipher = make_cipher();
        let iv = [42u8; 16];
        let plaintext = b"CTR mode encryption test!";
        let encrypted = encrypt(&cipher, plaintext, ModeOfOperation::CTR, Some(&iv));
        let decrypted = decrypt(&cipher, &encrypted, ModeOfOperation::CTR, Some(&iv)).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ecb_deterministic() {
        let cipher = make_cipher();
        let plaintext = b"Deterministic!!!!";
        let e1 = encrypt(&cipher, plaintext, ModeOfOperation::ECB, None);
        let e2 = encrypt(&cipher, plaintext, ModeOfOperation::ECB, None);
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_cbc_different_iv() {
        let cipher = make_cipher();
        let plaintext = b"Same plaintext!!";
        let iv1 = [0u8; 16];
        let iv2 = [1u8; 16];
        let e1 = encrypt(&cipher, plaintext, ModeOfOperation::CBC, Some(&iv1));
        let e2 = encrypt(&cipher, plaintext, ModeOfOperation::CBC, Some(&iv2));
        assert_ne!(e1, e2);
    }

    #[test]
    fn test_padding() {
        let data = b"test";
        let padded = pkcs7_pad(data, 16);
        assert_eq!(padded.len(), 16);
        let unpadded = pkcs7_unpad(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_empty_plaintext() {
        let cipher = make_cipher();
        let encrypted = encrypt(&cipher, b"", ModeOfOperation::ECB, None);
        let decrypted = decrypt(&cipher, &encrypted, ModeOfOperation::ECB, None).unwrap();
        assert_eq!(decrypted, b"");
    }
}
