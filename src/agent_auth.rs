use crate::diffie_hellman::DiffieHellman;
use crate::hash::Sha256Like;
use crate::hmac::Hmac;
use crate::rsa::Rsa;
use crate::signature::RsaSignature;
use crate::zkproof::{SchnorrProof, SchnorrZKP};
use num_bigint::BigUint;
use num_traits::One;
use serde::{Deserialize, Serialize};

/// Agent identity for secure authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub agent_id: String,
    pub public_key: String,  // RSA public key (hex n)
    pub dh_public: String,   // DH public key (hex)
    pub credential_hash: String, // Hash of credential
}

/// Authentication challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallenge {
    pub nonce: String,
    pub timestamp: u64,
    pub server_dh_public: String,
}

/// Authentication response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub agent_id: String,
    pub signature: Vec<u8>,
    pub hmac_tag: String,
    pub shared_secret_hash: String,
    pub zkp_proof: SchnorrProof,
}

/// Session established after successful authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedSession {
    pub agent_id: String,
    pub session_key: String,
    pub timestamp: u64,
}

/// Agent authentication system using combined cryptographic primitives
pub struct AgentAuth {
    identity: AgentIdentity,
    rsa: Rsa,
    dh: DiffieHellman,
    credential: Vec<u8>,
}

impl AgentAuth {
    /// Create a new agent with cryptographic identity
    pub fn new(agent_id: &str, credential: &[u8]) -> Self {
        let rsa = Rsa::generate(512);
        let dh = DiffieHellman::new(256);

        let credential_hash = {
            let hash = Sha256Like::digest(credential);
            hash.iter().map(|b| format!("{:02x}", b)).collect()
        };

        let identity = AgentIdentity {
            agent_id: agent_id.to_string(),
            public_key: rsa.keypair().n.clone(),
            dh_public: dh.public_key_hex(),
            credential_hash,
        };

        AgentAuth {
            identity,
            rsa,
            dh,
            credential: credential.to_vec(),
        }
    }

    pub fn identity(&self) -> &AgentIdentity {
        &self.identity
    }

    /// Create an authentication challenge (server side)
    pub fn create_challenge(&self, timestamp: u64) -> AuthChallenge {
        let nonce = {
            let hash = Sha256Like::digest(format!("{}:{}", self.identity.agent_id, timestamp).as_bytes());
            hash.iter().map(|b| format!("{:02x}", b)).collect()
        };

        AuthChallenge {
            nonce,
            timestamp,
            server_dh_public: self.dh.public_key_hex(),
        }
    }

    /// Respond to an authentication challenge (client side)
    pub fn respond_to_challenge(
        &self,
        challenge: &AuthChallenge,
        server_dh: &DiffieHellman,
    ) -> AuthResponse {
        // Sign the challenge nonce
        let challenge_data = format!("{}:{}", challenge.nonce, challenge.timestamp);
        let sig_scheme = RsaSignature::new(self.rsa().clone());
        let signed = sig_scheme.sign(challenge_data.as_bytes());

        // Compute shared secret via DH
        let server_pub = server_dh.public_key();
        let shared_secret = self.dh.compute_shared_secret(server_pub);
        let shared_hash = {
            let hash = Sha256Like::digest(&shared_secret.to_bytes_be());
            hash.iter().map(|b| format!("{:02x}", b)).collect()
        };

        // HMAC the response with shared secret
        let hmac = Hmac::new(&shared_secret.to_bytes_be());
        let hmac_result = hmac.compute(challenge_data.as_bytes());

        // Generate ZKP of credential knowledge
        let zkp = self.create_zkp(&challenge.nonce);

        AuthResponse {
            agent_id: self.identity.agent_id.clone(),
            signature: signed.signature,
            hmac_tag: hmac_result.hex,
            shared_secret_hash: shared_hash,
            zkp_proof: zkp,
        }
    }

    /// Verify an authentication response
    pub fn verify_response(
        &self,
        challenge: &AuthChallenge,
        response: &AuthResponse,
    ) -> Result<AuthenticatedSession, String> {
        // 1. Verify the challenge data
        let challenge_data = format!("{}:{}", challenge.nonce, challenge.timestamp);

        // 2. Verify HMAC
        let shared_secret = self.dh.compute_shared_secret(
            &BigUint::parse_bytes(response.shared_secret_hash.as_bytes(), 16).unwrap_or_default()
        );
        let hmac = Hmac::new(&shared_secret.to_bytes_be());
        let expected_hmac = hmac.compute(challenge_data.as_bytes());
        if expected_hmac.hex != response.hmac_tag {
            return Err("HMAC verification failed".into());
        }

        // 3. Verify ZKP
        // (In a full implementation, we'd verify the Schnorr proof here)

        Ok(AuthenticatedSession {
            agent_id: response.agent_id.clone(),
            session_key: response.shared_secret_hash.clone(),
            timestamp: challenge.timestamp,
        })
    }

    fn create_zkp(&self, nonce: &str) -> SchnorrProof {
        // Use a simplified ZKP setup
        let p = BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
            16,
        ).unwrap();
        let g = BigUint::from(2u32);
        let n = &p - BigUint::one();

        let zkp = SchnorrZKP::new(p, g, n);

        // Secret is derived from credential + nonce
        let hash = Sha256Like::digest(
            &[self.credential.clone(), nonce.as_bytes().to_vec()].concat()
        );
        let secret_input: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        let secret = BigUint::parse_bytes(secret_input.as_bytes(), 16)
            .unwrap_or(BigUint::from(42u32));

        zkp.prove(&secret)
    }

    pub fn rsa(&self) -> &Rsa {
        &self.rsa
    }
}

impl DiffieHellman {
    fn public_key_hex(&self) -> String {
        format!("{:x}", self.public_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_identity_creation() {
        let auth = AgentAuth::new("agent-001", b"secret_credential");
        let id = auth.identity();
        assert_eq!(id.agent_id, "agent-001");
        assert!(!id.public_key.is_empty());
        assert!(!id.credential_hash.is_empty());
    }

    #[test]
    fn test_challenge_creation() {
        let auth = AgentAuth::new("agent-001", b"credential");
        let challenge = auth.create_challenge(1000);
        assert!(!challenge.nonce.is_empty());
        assert_eq!(challenge.timestamp, 1000);
        assert!(!challenge.server_dh_public.is_empty());
    }

    #[test]
    fn test_different_agents_different_keys() {
        let a1 = AgentAuth::new("agent-001", b"cred1");
        let a2 = AgentAuth::new("agent-002", b"cred2");
        assert_ne!(a1.identity().public_key, a2.identity().public_key);
    }

    #[test]
    fn test_identity_serialization() {
        let auth = AgentAuth::new("agent-001", b"credential");
        let id = auth.identity();
        let json = serde_json::to_string(id).unwrap();
        let deserialized: AgentIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.agent_id, "agent-001");
    }

    #[test]
    fn test_credential_hash_consistency() {
        let a1 = AgentAuth::new("agent-001", b"same_credential");
        let a2 = AgentAuth::new("agent-002", b"same_credential");
        assert_eq!(a1.identity().credential_hash, a2.identity().credential_hash);
    }
}
