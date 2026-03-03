pub mod barretenberg;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::errors::ProverError;

/// Output from a proof generation invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOutput {
    /// Raw proof bytes produced by the proving backend.
    pub proof: Vec<u8>,
    /// Wall-clock time for proof generation in milliseconds.
    pub proving_time_ms: u64,
}

/// Trait for proof generation backends.
///
/// Designed for both the real Barretenberg CLI backend and mock
/// implementations for testing. Object-safe via `async_trait`.
#[async_trait]
pub trait ProverBackend: Send + Sync {
    /// Generate a proof for the given circuit using the provided witness.
    async fn prove(&self, circuit_id: &str, witness: &[u8]) -> Result<ProofOutput, ProverError>;

    /// Verify a proof against the circuit's verification key.
    /// Returns `true` if the proof is valid, `false` otherwise.
    async fn verify(&self, circuit_id: &str, proof: &[u8]) -> Result<bool, ProverError>;
}
