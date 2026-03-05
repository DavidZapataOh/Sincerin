//! Read-only ProofRegistry client.
//!
//! Provides query access to the ProofRegistry contract on the Sincerin L1.
//! Write operations (registerProof) are handled atomically by Coordinator.sol
//! via the `onlyCoordinator` modifier — the collector never calls
//! ProofRegistry directly for writes.
//!
//! Available queries:
//! - `is_verified(proofId, merkleProof)` — verify inclusion in the Merkle tree
//! - `get_merkle_root()` — fetch the current root hash

use alloy::primitives::{Address, FixedBytes};
use alloy::providers::RootProvider;
use alloy::sol;
use alloy::transports::http::reqwest::Url;
use anyhow::Result;
use tracing::info;

use crate::config::CollectorConfig;

// ---------------------------------------------------------------------------
// Solidity interface bindings (read-only)
// ---------------------------------------------------------------------------

sol! {
    #[sol(rpc)]
    interface IProofRegistry {
        function isVerified(
            bytes32 proofId,
            bytes32[] calldata merkleProof
        ) external view returns (bool);

        function getMerkleRoot() external view returns (bytes32);

        function getProofMetadata(bytes32 proofId) external view returns (
            bytes32 circuitId,
            uint256 leafIndex,
            uint256 timestamp,
            bool exists
        );
    }
}

// ---------------------------------------------------------------------------
// RegistryClient
// ---------------------------------------------------------------------------

/// Read-only client for the ProofRegistry contract.
///
/// Uses an unsigned HTTP provider since all operations are `view` calls.
pub struct RegistryClient {
    provider: RootProvider,
    registry_address: Address,
}

impl RegistryClient {
    /// Create a new RegistryClient from collector configuration.
    pub fn new(config: &CollectorConfig) -> Result<Self> {
        let url: Url = config.l1_rpc_url.parse()?;
        let provider = RootProvider::new_http(url);
        let registry_address: Address = config.registry_address.parse()?;

        info!(
            registry = %registry_address,
            "RegistryClient initialized"
        );

        Ok(Self {
            provider,
            registry_address,
        })
    }

    /// Check whether a proof has been verified and is in the Merkle tree.
    ///
    /// Returns `true` if the proof ID is present at the given Merkle path.
    pub async fn is_verified(
        &self,
        proof_id: &str,
        merkle_proof: &[Vec<u8>],
    ) -> Result<bool> {
        let proof_id_bytes: FixedBytes<32> = proof_id.parse()?;

        let merkle_hashes: Vec<FixedBytes<32>> = merkle_proof
            .iter()
            .map(|h| {
                let arr: [u8; 32] = h
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("merkle proof element must be 32 bytes"))?;
                Ok(FixedBytes::from(arr))
            })
            .collect::<Result<Vec<_>>>()?;

        let registry = IProofRegistry::new(self.registry_address, &self.provider);
        let result = registry
            .isVerified(proof_id_bytes, merkle_hashes)
            .call()
            .await?;

        Ok(result)
    }

    /// Fetch the current Merkle root from the ProofRegistry.
    pub async fn get_merkle_root(&self) -> Result<String> {
        let registry = IProofRegistry::new(self.registry_address, &self.provider);
        let result = registry.getMerkleRoot().call().await?;
        Ok(format!("0x{}", hex::encode(result)))
    }

    /// Fetch metadata for a specific proof.
    ///
    /// Returns `None` if the proof does not exist in the registry.
    pub async fn get_proof_metadata(
        &self,
        proof_id: &str,
    ) -> Result<Option<ProofMetadata>> {
        let proof_id_bytes: FixedBytes<32> = proof_id.parse()?;
        let registry = IProofRegistry::new(self.registry_address, &self.provider);

        let result = registry
            .getProofMetadata(proof_id_bytes)
            .call()
            .await?;

        if !result.exists {
            return Ok(None);
        }

        Ok(Some(ProofMetadata {
            circuit_id: format!("0x{}", hex::encode(result.circuitId.as_slice())),
            leaf_index: result.leafIndex.to::<u64>(),
            timestamp: result.timestamp.to::<u64>(),
        }))
    }

    /// Returns the registry contract address.
    pub fn registry_address(&self) -> Address {
        self.registry_address
    }
}

/// Metadata for a verified proof stored in the ProofRegistry.
#[derive(Debug, Clone)]
pub struct ProofMetadata {
    pub circuit_id: String,
    pub leaf_index: u64,
    pub timestamp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_client_new_success() {
        let config = CollectorConfig {
            l1_rpc_url: "http://localhost:9650/ext/bc/sincerin/rpc".to_string(),
            registry_address: "0x0000000000000000000000000000000000000002".to_string(),
            ..CollectorConfig::default()
        };

        let client = RegistryClient::new(&config).expect("should create client");
        assert_eq!(
            client.registry_address(),
            "0x0000000000000000000000000000000000000002"
                .parse::<Address>()
                .unwrap()
        );
    }

    #[test]
    fn test_registry_client_rejects_bad_address() {
        let config = CollectorConfig {
            l1_rpc_url: "http://localhost:9650/ext/bc/sincerin/rpc".to_string(),
            registry_address: "not-an-address".to_string(),
            ..CollectorConfig::default()
        };

        assert!(RegistryClient::new(&config).is_err());
    }

    #[test]
    fn test_proof_metadata_fields() {
        let meta = ProofMetadata {
            circuit_id: "0xabc".to_string(),
            leaf_index: 42,
            timestamp: 1700000000,
        };

        assert_eq!(meta.leaf_index, 42);
        assert_eq!(meta.timestamp, 1700000000);
    }
}
