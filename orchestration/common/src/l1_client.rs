//! L1 client for interacting with the Sincerin Avalanche L1.
//!
//! Provides typed bindings to the Coordinator and ProofRegistry contracts
//! via the alloy `sol!` macro, and a thin async client that wraps an HTTP
//! provider. Write operations (submit_proof) are intentionally stubbed --
//! they require a signer, which lands in Sprint 2.
//!
//! Design notes (Buterin): one provider type, one serialization format,
//! one transport -- no fragmentation.
//! Design notes (Drake): read-only verification first; signing is a
//! separate security boundary added later.

use alloy::primitives::{Address, FixedBytes};
use alloy::providers::RootProvider;
use alloy::transports::http::reqwest::Url;
use anyhow::Result;

// ---------------------------------------------------------------------------
// Solidity interface bindings
// ---------------------------------------------------------------------------

alloy::sol! {
    /// Coordinator contract -- manages proof request lifecycle.
    #[sol(rpc)]
    interface ICoordinator {
        event ProofRequested(
            bytes32 indexed requestId,
            bytes32 indexed circuitId,
            address indexed requester,
            uint256 maxFee,
            uint256 deadline
        );

        event ProofVerified(
            bytes32 indexed requestId,
            bytes32 indexed proofId,
            bytes32 circuitId,
            uint256 timestamp
        );

        function submitProof(
            bytes32 requestId,
            bytes calldata proof,
            bytes calldata publicInputs
        ) external;

        function getRequest(bytes32 requestId) external view returns (
            bytes32, bytes32, address, uint256, uint256, address, uint8, uint256
        );
    }

    /// ProofRegistry contract -- Merkle tree of verified proofs.
    #[sol(rpc)]
    interface IProofRegistry {
        function isVerified(
            bytes32 proofId,
            bytes32[] calldata merkleProof
        ) external view returns (bool);

        function getMerkleRoot() external view returns (bytes32);
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for connecting to the Sincerin L1.
///
/// All addresses are hex-encoded (with or without `0x` prefix).
/// `chain_id` defaults to the Sincerin L1 chain ID from genesis.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct L1Config {
    pub rpc_url: String,
    pub ws_url: String,
    pub coordinator_address: String,
    pub proof_registry_address: String,
    pub prover_registry_address: String,
    pub chain_id: u64,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Async client for the Sincerin L1.
///
/// Uses an HTTP provider (reqwest) for read-only calls. Write operations
/// are stubbed until Sprint 2 adds wallet/signer integration.
///
/// The provider is type-erased behind `RootProvider` so the client
/// is `Send + Sync` and easy to store in shared state. All contract calls
/// go through alloy's generated `CallBuilder` pattern.
pub struct L1Client {
    provider: alloy::providers::RootProvider,
    coordinator_address: Address,
    proof_registry_address: Address,
    prover_registry_address: Address,
    chain_id: u64,
}

impl L1Client {
    /// Create a new L1 client from the given configuration.
    ///
    /// Parses contract addresses and builds an HTTP provider via
    /// `ProviderBuilder`. Fails if addresses are malformed or the
    /// URL is unreachable.
    pub async fn new(config: &L1Config) -> Result<Self> {
        let url: Url = config.rpc_url.parse()?;
        let provider = RootProvider::new_http(url);

        let coordinator_address: Address = config.coordinator_address.parse()?;
        let proof_registry_address: Address = config.proof_registry_address.parse()?;
        let prover_registry_address: Address = config.prover_registry_address.parse()?;

        Ok(Self {
            provider,
            coordinator_address,
            proof_registry_address,
            prover_registry_address,
            chain_id: config.chain_id,
        })
    }

    /// Check whether a proof has been verified on-chain.
    ///
    /// Calls `IProofRegistry.isVerified(proofId, merkleProof)` against
    /// the L1. Each element in `merkle_proof` must be exactly 32 bytes.
    pub async fn is_verified(&self, proof_id: &str, merkle_proof: &[Vec<u8>]) -> Result<bool> {
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

        let registry = IProofRegistry::new(self.proof_registry_address, &self.provider);

        let result = registry
            .isVerified(proof_id_bytes, merkle_hashes)
            .call()
            .await?;

        Ok(result)
    }

    /// Fetch the current Merkle root from the ProofRegistry.
    ///
    /// Returns the root as a hex-encoded string (with `0x` prefix).
    pub async fn get_merkle_root(&self) -> Result<String> {
        let registry = IProofRegistry::new(self.proof_registry_address, &self.provider);

        let result = registry.getMerkleRoot().call().await?;

        Ok(format!("0x{}", hex::encode(result)))
    }

    /// Submit a proof to the Coordinator contract.
    ///
    /// **Stub** -- returns an error directing callers to Sprint 2.
    /// Write operations require a signer (private key / wallet) which
    /// is a separate security boundary. Read operations are safe to
    /// expose now; signing is deferred intentionally (Drake: security
    /// first, then find designs that achieve both).
    pub async fn submit_proof(
        &self,
        _request_id: &str,
        _proof: &[u8],
        _public_inputs: &[u8],
    ) -> Result<String> {
        anyhow::bail!("submit_proof requires signer - implement in Sprint 2")
    }

    // -- Accessors -----------------------------------------------------------

    /// Returns the coordinator contract address.
    pub fn coordinator_address(&self) -> Address {
        self.coordinator_address
    }

    /// Returns the proof registry contract address.
    pub fn proof_registry_address(&self) -> Address {
        self.proof_registry_address
    }

    /// Returns the prover registry contract address.
    pub fn prover_registry_address(&self) -> Address {
        self.prover_registry_address
    }

    /// Returns the chain ID this client is configured for.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> L1Config {
        L1Config {
            rpc_url: "http://127.0.0.1:9650/ext/bc/sincerin/rpc".to_string(),
            ws_url: "ws://127.0.0.1:9650/ext/bc/sincerin/ws".to_string(),
            coordinator_address: "0x0000000000000000000000000000000000000001".to_string(),
            proof_registry_address: "0x0000000000000000000000000000000000000002".to_string(),
            prover_registry_address: "0x0000000000000000000000000000000000000003".to_string(),
            chain_id: 77777,
        }
    }

    #[test]
    fn test_l1_config_defaults() {
        let config = test_config();

        assert_eq!(config.chain_id, 77777);
        assert!(config.rpc_url.contains("sincerin"));
        assert!(config.ws_url.starts_with("ws://"));
        assert_eq!(
            config.coordinator_address,
            "0x0000000000000000000000000000000000000001"
        );
        assert_eq!(
            config.proof_registry_address,
            "0x0000000000000000000000000000000000000002"
        );
        assert_eq!(
            config.prover_registry_address,
            "0x0000000000000000000000000000000000000003"
        );
    }

    #[tokio::test]
    async fn test_l1_client_new_parses_config() {
        let config = test_config();

        // new() only parses config + builds an HTTP client -- no network call.
        let client = L1Client::new(&config).await.expect("should parse config");

        assert_eq!(client.chain_id(), 77777);
        assert_eq!(
            client.coordinator_address(),
            "0x0000000000000000000000000000000000000001"
                .parse::<Address>()
                .unwrap()
        );
        assert_eq!(
            client.proof_registry_address(),
            "0x0000000000000000000000000000000000000002"
                .parse::<Address>()
                .unwrap()
        );
        assert_eq!(
            client.prover_registry_address(),
            "0x0000000000000000000000000000000000000003"
                .parse::<Address>()
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_submit_proof_stub_errors() {
        let config = test_config();
        let client = L1Client::new(&config).await.unwrap();

        let result = client
            .submit_proof(
                "0x0000000000000000000000000000000000000000000000000000000000000abc",
                &[],
                &[],
            )
            .await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Sprint 2"),
            "error should mention Sprint 2, got: {err_msg}"
        );
    }

    #[tokio::test]
    #[ignore] // Requires a running Sincerin L1 node
    async fn test_l1_client_connects() {
        let config = test_config();
        let client = L1Client::new(&config).await.unwrap();

        let root = client.get_merkle_root().await;
        assert!(root.is_ok(), "should connect to L1 and fetch merkle root");
    }
}
