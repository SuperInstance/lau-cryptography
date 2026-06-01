# lau-cryptography

> Cryptographic primitives and protocols — the math behind secure communication

## What This Does

Cryptographic primitives and protocols — the math behind secure communication. Part of the PLATO/LAU ecosystem — a mathematically rigorous framework for building educational agents that learn, teach, and evolve.

## The Key Idea

This crate implements the core abstractions needed for its domain, with a focus on correctness, composability, and conservation guarantees. Every public type is serializable (serde), every algorithm is tested, and every invariant is verified.

## Install

```bash
cargo add lau-cryptography
```

## Quick Start

See the API Reference below for complete usage. Key entry points:

```rust
use lau_cryptography::*;
// See types and methods below for complete usage
```

## API Reference

```rust
pub struct AgentIdentity 
pub struct AuthChallenge 
pub struct AuthResponse 
pub struct AuthenticatedSession 
pub struct AgentAuth 
    pub fn new(agent_id: &str, credential: &[u8]) -> Self 
    pub fn identity(&self) -> &AgentIdentity 
    pub fn create_challenge(&self, timestamp: u64) -> AuthChallenge 
    pub fn respond_to_challenge(
    pub fn verify_response(
    pub fn rsa(&self) -> &Rsa 
pub struct DhParams 
pub struct DhKeyPair 
pub struct DiffieHellman 
    pub fn new(bit_size: usize) -> Self 
    pub fn public_key(&self) -> &BigUint 
    pub fn params(&self) -> &DhParams 
    pub fn compute_shared_secret(&self, other_public: &BigUint) -> BigUint 
pub struct RsaKeyPair 
pub struct Rsa 
    pub fn generate(bit_size: usize) -> Self 
    pub fn from_keypair(keypair: RsaKeyPair) -> Self 
    pub fn keypair(&self) -> &RsaKeyPair 
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> 
    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> 
    pub fn sign(&self, message: &[u8]) -> Vec<u8> 
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool 
    pub fn is_probably_prime(n: &BigUint) -> bool 
pub struct Sha256Like 
    pub fn new() -> Self 
    pub fn update(&mut self, data: &[u8]) 
    pub fn finalize(mut self) -> Vec<u8> 
    pub fn digest(data: &[u8]) -> Vec<u8> 
pub struct HashResult 
    pub fn from_bytes(bytes: Vec<u8>) -> Self 
pub struct RsaSignature 
pub struct SignedMessage 
    pub fn new(rsa: Rsa) -> Self 
    pub fn generate(bit_size: usize) -> Self 
    pub fn sign(&self, message: &[u8]) -> SignedMessage 
    pub fn verify(&self, signed: &SignedMessage) -> bool 
    pub fn verify_with_public_key(signed: &SignedMessage) -> bool 
    pub fn rsa(&self) -> &Rsa 
pub struct EcPoint 
    pub fn new(x: BigUint, y: BigUint) -> Self 
    pub fn infinity() -> Self 
    pub fn is_infinity(&self) -> bool 
    pub fn x(&self) -> Option<BigUint> 
    pub fn y(&self) -> Option<BigUint> 
pub struct EllipticCurve 
    pub fn new(a: BigUint, b: BigUint, p: BigUint, n: BigUint, g: EcPoint) -> Self 
    pub fn secp256k1_small() -> Self 
    pub fn is_on_curve(&self, point: &EcPoint) -> bool 
    pub fn point_add(&self, p1: &EcPoint, p2: &EcPoint) -> EcPoint 
    pub fn scalar_multiply(&self, k: &BigUint, point: &EcPoint) -> EcPoint 
    pub fn point_negate(&self, point: &EcPoint) -> EcPoint 
    pub fn generate_keypair(&self) -> (BigUint, EcPoint) 
pub struct SchnorrCommitment 
pub struct SchnorrChallenge 
pub struct SchnorrResponse 
```

## How It Works

Read the source in `src/` for full implementation details. All algorithms are documented with inline comments explaining the mathematical foundations.

## The Math

This crate implements formal mathematical constructs. See the source documentation for theorem statements and proofs of correctness.

## Testing

**67 tests** covering construction, serialization, correctness properties, edge cases, and composability with other lau-* crates.

## License

MIT
