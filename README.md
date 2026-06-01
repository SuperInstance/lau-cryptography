# lau-cryptography

**Cryptographic primitives in pure Rust** — RSA, Diffie-Hellman, elliptic curve arithmetic, hash functions, HMAC, symmetric encryption, digital signatures, Schnorr zero-knowledge proofs, and multi-protocol agent authentication.

> *Teaching crypto by building every layer from scratch.*

---

## What This Does

This library implements the foundational building blocks of cryptography from the ground up. Every module is a self-contained primitive that can be used independently or composed into larger protocols. The implementations are educational — they expose the internals clearly, follow standard constructions, and include thorough test suites — but they are **not production-grade** (use ring or OpenSSL for that).

The nine modules break down as:

| Module | What you get |
|---|---|
| `hash` | Merkle-Damgård hash function with SHA-256-like compression |
| `symmetric` | Feistel-network block cipher with CBC/CTR/OFB modes |
| `rsa` | RSA key generation, OAEP-padding encrypt/decrypt, sign/verify |
| `diffie_hellman` | Diffie-Hellman key exchange with safe-prime generation |
| `elliptic_curve` | Elliptic curve arithmetic over finite fields, secp256k1-like curve |
| `signature` | RSA-based digital signatures (hash-then-sign) |
| `hmac` | HMAC construction over the built-in hash |
| `zkproof` | Schnorr zero-knowledge proof of discrete log knowledge |
| `agent_auth` | Full multi-protocol agent authentication combining RSA, DH, HMAC, ZKP |

**Stats:** ~2,100 lines of source, 67 tests, zero unsafe code.

---

## Key Idea

Modern cryptography is built from a small number of hard mathematical problems: integer factorization (RSA), discrete logarithms (DH, EC), and collision resistance (hash functions). This library implements each layer so you can see exactly how the abstraction stack works:

```
Agent Authentication
  └── RSA signatures + DH key exchange + HMAC + ZKP
        ├── RSA (modular exponentiation, prime generation)
        ├── Diffie-Hellman (safe primes, discrete log)
        ├── HMAC (hash + XOR construction)
        └── Schnorr ZKP (interactive proof of knowledge)
              └── Hash function (Merkle-Damgård, compression)
```

Each layer is independently testable and understandable.

---

## Install

Add to your `Cargo.toml`:

```toml
[dependencies]
lau-cryptography = "0.1"
```

### Dependencies

- **num-bigint** — arbitrary-precision integers for RSA and DH
- **num-traits** — numeric trait abstractions
- **nalgebra** — linear algebra (for some internal computations)
- **serde** — serialization of keys, proofs, ciphertexts
- **rand** — cryptographically secure random number generation (`OsRng`)

---

## Quick Start

### Hash a message

```rust
use lau_cryptography::Sha256Like;

let digest = Sha256Like::digest(b"hello world");
println!("hash = {}", digest.iter().map(|b| format!("{:02x}", b)).collect::<String>());
```

The `Sha256Like` struct implements streaming via `new()` → `update()` → `finalize()`, or the one-shot `digest()` convenience method.

### Symmetric encryption

```rust
use lau_cryptography::{BlockCipher, ModeOfOperation};

let cipher = BlockCipher::new(b"my-secret-key-16");
let plaintext = b"Hello, world!123"; // must be 16 bytes

let ciphertext = cipher.encrypt_block(plaintext);
let decrypted = cipher.decrypt_block(&ciphertext);
assert_eq!(decrypted, *plaintext);
```

Use `ModeOfOperation` for CBC, CTR, or OFB with automatic padding.

### RSA encrypt/decrypt

```rust
use lau_cryptography::Rsa;

let rsa = Rsa::generate(2048);
let plaintext = b"secret message";
let ciphertext = rsa.encrypt(plaintext);
let decrypted = rsa.decrypt(&ciphertext);
assert_eq!(decrypted, plaintext);
```

Key generation produces safe primes, and encryption uses OAEP-like padding.

### Diffie-Hellman key exchange

```rust
use lau_cryptography::DiffieHellman;

let alice = DiffieHellman::new(2048);
let bob = DiffieHellman::new(2048);

// Exchange public keys
let alice_secret = alice.shared_secret(bob.public_key());
let bob_secret = bob.shared_secret(alice.public_key());
assert_eq!(alice_secret, bob_secret); // Same shared secret!
```

### Digital signatures

```rust
use lau_cryptography::RsaSignature;

let signer = RsaSignature::generate(2048);
let signed = signer.sign(b"important message");
assert!(signer.verify(&signed));

// Anyone can verify with just the public key
assert!(RsaSignature::verify_with_public_key(&signed));
```

### Schnorr zero-knowledge proof

```rust
use lau_cryptography::SchnorrZKP;
use num_bigint::BigUint;

let p = BigUint::parse_bytes(b"FFFFFFFFFFFFFFC5", 16).unwrap(); // prime
let g = BigUint::from(2u32);                                     // generator
let n = p.clone();                                                // order
let x = BigUint::from(42u32);                                     // secret

let zkp = SchnorrZKP::new(p, g, n);
let proof = zkp.prove(&x);
assert!(zkp.verify(&proof)); // Verifier is convinced you know x, without learning x
```

### Agent authentication

```rust
use lau_cryptography::AgentAuth;

let agent = AgentAuth::new("agent-007", b"password123");
let challenge = agent.create_challenge();

// On the "server" side:
let response = agent.respond_to_challenge(&challenge);
let session = AgentAuth::verify_session(&response, &challenge);
assert!(session.is_ok());
```

`AgentAuth` combines RSA signing, DH key exchange, HMAC authentication, and a Schnorr ZKP into a single authentication protocol that establishes a verified, key-derived session.

---

## API Reference

### `hash` — `Sha256Like`

| Method | Description |
|---|---|
| `Sha256Like::new()` | Create a streaming hash instance (initial state = H₀) |
| `.update(data)` | Absorb data into the hash |
| `.finalize()` | Produce the 32-byte digest (one-shot per instance) |
| `Sha256Like::digest(data)` | One-shot convenience: hash → 32 bytes |

Construction: Merkle-Damgård with 64-round compression using the standard SHA-256 schedule (Ch, Maj, Σ₀, Σ₁, σ₀, σ₁), initial hash values, and round constants.

### `symmetric` — `BlockCipher` + `ModeOfOperation`

| Type / Method | Description |
|---|---|
| `BlockCipher::new(key)` | 16-round Feistel cipher, 16-byte blocks |
| `.encrypt_block([u8;16])` / `.decrypt_block([u8;16])` | Single-block encrypt/decrypt |
| `ModeOfOperation` | `Cbc`, `Ctr`, `Ofb` — handle padding and chaining |

The Feistel structure guarantees reversibility regardless of the round function. Key expansion uses iterative hashing of the key material.

### `rsa` — `Rsa`

| Method | Description |
|---|---|
| `Rsa::generate(bits)` | Generate key pair with two safe primes, e = 65537 |
| `Rsa::from_keypair(kp)` | Reconstruct from serialized `RsaKeyPair` |
| `.keypair()` | Access the serializable key pair |
| `.encrypt(plaintext)` | RSA-OAEP encrypt |
| `.decrypt(ciphertext)` | RSA-OAEP decrypt |
| `.sign(message)` | Hash-then-sign (deterministic) |
| `.verify(message, sig)` | Hash-then-verify |

OAEP padding: `[0x00…0x01] [message] [hash(message)]` with length validation.

### `diffie_hellman` — `DiffieHellman`

| Method | Description |
|---|---|
| `DiffieHellman::new(bits)` | Generate safe prime p, generator g = 2, random private key |
| `.public_key()` | g^x mod p |
| `.params()` | Serialize (p, g) for sharing |
| `.shared_secret(other_public)` | Compute shared secret from peer's public key |
| `DiffieHellman::generate_safe_prime(bits)` | Internal: p where (p−1)/2 is also prime |

### `elliptic_curve` — `EllipticCurve`

| Type / Method | Description |
|---|---|
| `EllipticCurve::new(a, b, p, n, g)` | Curve y² = x³ + ax + b (mod p) |
| `EllipticCurve::secp256k1_small()` | secp256k1-like curve for testing |
| `.add(p1, p2)` | Point addition |
| `.double(p)` | Point doubling |
| `.scalar_mult(k, p)` | Double-and-add scalar multiplication |
| `.is_on_curve(p)` | Verify point satisfies the curve equation |
| `EcPoint` | Affine point with optional coordinates (None = point at infinity) |

### `signature` — `RsaSignature`

| Method | Description |
|---|---|
| `RsaSignature::generate(bits)` | Create signer with fresh RSA key |
| `.sign(message)` | Returns `SignedMessage` with message, signature, and public key |
| `.verify(signed)` | Verify using stored RSA instance |
| `RsaSignature::verify_with_public_key(signed)` | Verify using only the public key from the `SignedMessage` |

### `hmac` — `Hmac`

| Method | Description |
|---|---|
| `Hmac::new(key)` | Create HMAC instance |
| `.compute(message)` | Returns `HmacResult` with raw bytes and hex string |
| `.verify(message, expected)` | Constant-time comparison |

Construction: HMAC(K, m) = H((K' ⊕ opad) ‖ H((K' ⊕ ipad) ‖ m)) with block_size = 64.

### `zkproof` — `SchnorrZKP`

| Method | Description |
|---|---|
| `SchnorrZKP::new(p, g, n)` | Initialize with group parameters |
| `.prove(x)` | Prove knowledge of discrete log of y = g^x |
| `.verify(proof)` | Verify the proof without learning x |

Protocol (non-interactive via Fiat-Shamir):
1. Prover picks random r, computes R = g^r
2. Challenge c = H(g, y, R)
3. Response s = r + c·x mod n
4. Verifier checks: g^s = R · y^c

### `agent_auth` — `AgentAuth`

| Type / Method | Description |
|---|---|
| `AgentAuth::new(id, credential)` | Create agent identity with RSA + DH + credential hash |
| `.create_challenge()` | Generate `AuthChallenge` with nonce, timestamp, server DH public |
| `.respond_to_challenge(challenge)` | Build `AuthResponse` with signature, HMAC, ZKP proof |
| `AgentAuth::verify_session(response, challenge)` | Verify all cryptographic components, return `AuthenticatedSession` |
| `AgentIdentity` | Serializable agent profile with RSA public key and DH public key |

The authentication protocol combines:
- **RSA signature** → proves identity
- **DH key exchange** → establishes shared secret
- **HMAC** → authenticates the challenge-response
- **Schnorr ZKP** → proves knowledge of the private key without revealing it

---

## How It Works

### Hash Function (Merkle-Damgård)

The hash uses the Merkle-Damgård construction: the message is padded (SHA-style: append 0x80, zeros, then the 64-bit length), split into 512-bit blocks, and each block is processed by a compression function that mixes the block into a 256-bit state using 64 rounds of Ch, Maj, and Σ rotations. The initial state comes from the fractional parts of square roots of the first 8 primes.

### Symmetric Cipher (Feistel Network)

A 16-round Feistel cipher splits each 128-bit block into left and right halves. Each round applies a non-invertible round function to the right half and XORs the result with the left half, then swaps. Decryption is identical to encryption but with round keys in reverse order — the beauty of Feistel is that the round function F doesn't need to be invertible.

### RSA

Key generation: find two large primes p, q, compute n = pq, φ = (p−1)(q−1), set e = 65537, compute d = e⁻¹ mod φ. Encryption: c = m^e mod n. Decryption: m = c^d mod n. Security relies on the hardness of factoring n into p and q.

### Diffie-Hellman

Two parties agree on a prime p and generator g. Each picks a random private key and shares g^x mod p. The shared secret is (g^y)^x = (g^x)^y = g^xy mod p. An eavesdropper sees only g^x and g^y but cannot compute g^xy without solving the discrete logarithm problem.

### Elliptic Curve Cryptography

Points on the curve y² = x³ + ax + b (mod p) form an abelian group. Point addition is geometric: draw a line through two points, the third intersection is the negation of the sum. Scalar multiplication is repeated addition (double-and-add). The discrete log problem on elliptic curves (given P and kP, find k) is harder than in ℤ_p*, allowing smaller keys for equivalent security.

### Schnorr Zero-Knowledge Proof

The prover wants to convince the verifier they know x such that y = g^x, without revealing x. The protocol works because s = r + cx, so g^s = g^(r+cx) = g^r · (g^x)^c = R · y^c. The verifier checks this equation without ever seeing x. The Fiat-Shamir heuristic replaces the interactive challenge with H(g, y, R) for non-interactive proofs.

---

## The Math

### Modular Arithmetic
All public-key operations work in ℤ_n (integers mod n). The key operation is modular exponentiation a^b mod n, computed efficiently via square-and-multiply.

### RSA Security
The RSA problem: given n, e, and c = m^e mod n, find m. Equivalent to factoring n = pq (believed but not proven). Key sizes: 2048 bits is standard, 4096 for high security.

### Discrete Logarithm Problem (DLP)
Given g and y = g^x mod p, find x. No known polynomial-time algorithm for classical computers. The security of DH and Schnorr ZKP rests on this.

### Elliptic Curve Discrete Logarithm Problem (ECDLP)
Given P and Q = kP on an elliptic curve, find k. Subexponential attacks exist for DLP over ℤ_p*, but only exponential attacks for ECDLP, which is why ECDSA uses 256-bit keys vs RSA's 2048-bit keys.

### HMAC Security
HMAC's security reduces to the collision resistance and pseudorandomness of the underlying hash function. Even if the hash has some weaknesses, HMAC often remains secure.

### Zero-Knowledge Properties
A ZKP satisfies three properties:
1. **Completeness**: an honest prover convinces an honest verifier
2. **Soundness**: a cheating prover cannot convince the verifier (except with negligible probability)
3. **Zero-knowledge**: the verifier learns nothing beyond the truth of the statement

---

## License

MIT
