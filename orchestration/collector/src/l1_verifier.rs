//! L1 Verifier — submits proofs to Coordinator.sol with a signer.
//!
//! This is the write-path counterpart to common's read-only L1Client.
//! It holds a wallet-enabled provider that can sign and broadcast
//! transactions to the Sincerin L1.
//!
//! The flow for a single proof:
//! 1. Encode calldata: `Coordinator.submitProof(requestId, proof, publicInputs)`
//! 2. Send transaction with gas limit from config
//! 3. Wait for receipt
//! 4. Parse `ProofVerified` event from receipt logs
//! 5. Return `VerificationResult` with tx_hash, gas_used, proof_id

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, Bytes, FixedBytes};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::transports::http::reqwest::Url;
use anyhow::Result;
use tracing::{debug, info};

use crate::config::CollectorConfig;

// ---------------------------------------------------------------------------
// Solidity interface bindings (same as common, but with send capability)
// ---------------------------------------------------------------------------

sol! {
    #[sol(rpc)]
    interface ICoordinator {
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
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Result of a successful on-chain proof verification.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Transaction hash on the Sincerin L1.
    pub tx_hash: String,
    /// Gas consumed by the transaction.
    pub gas_used: u64,
    /// Proof ID extracted from the ProofVerified event.
    pub proof_id: String,
    /// Circuit ID from the event.
    pub circuit_id: String,
    /// Block timestamp from the event.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// L1Verifier
// ---------------------------------------------------------------------------

/// Type alias for the wallet-enabled provider built by `ProviderBuilder`.
///
/// `ProviderBuilder::new()` in alloy 1.7.x applies recommended fillers
/// (gas, nonce, chain-id, blob-gas) by default. Adding `.wallet()` wraps
/// them with a `WalletFiller`.
type WalletProvider = alloy::providers::fillers::FillProvider<
    alloy::providers::fillers::JoinFill<
        alloy::providers::fillers::JoinFill<
            alloy::providers::Identity,
            alloy::providers::fillers::JoinFill<
                alloy::providers::fillers::GasFiller,
                alloy::providers::fillers::JoinFill<
                    alloy::providers::fillers::BlobGasFiller,
                    alloy::providers::fillers::JoinFill<
                        alloy::providers::fillers::NonceFiller,
                        alloy::providers::fillers::ChainIdFiller,
                    >,
                >,
            >,
        >,
        alloy::providers::fillers::WalletFiller<EthereumWallet>,
    >,
    alloy::providers::RootProvider,
>;

/// Submits proofs to Coordinator.sol and parses verification results.
///
/// Uses an alloy `FillProvider` with wallet capabilities to sign
/// transactions. The wallet is derived from the private key in config.
pub struct L1Verifier {
    provider: WalletProvider,
    coordinator_address: Address,
    gas_limit: u64,
}

impl L1Verifier {
    /// Create a new L1Verifier from collector configuration.
    ///
    /// Parses the signer private key and builds a wallet-enabled provider.
    pub fn new(config: &CollectorConfig) -> Result<Self> {
        let url: Url = config.l1_rpc_url.parse()?;

        let signer: PrivateKeySigner = config.signer_private_key.parse()?;
        let wallet = EthereumWallet::from(signer);

        // ProviderBuilder::new() already applies recommended fillers
        // (gas, nonce, chain-id) in alloy 1.7.x.
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(url);

        let coordinator_address: Address = config.coordinator_address.parse()?;

        info!(
            coordinator = %coordinator_address,
            gas_limit = config.gas_limit_submit,
            "L1Verifier initialized"
        );

        Ok(Self {
            provider,
            coordinator_address,
            gas_limit: config.gas_limit_submit,
        })
    }

    /// Submit a proof to Coordinator.submitProof() and wait for the receipt.
    ///
    /// Returns a `VerificationResult` on success, or an error if:
    /// - The transaction reverts (proof invalid)
    /// - The ProofVerified event is missing from the receipt
    /// - An RPC/network error occurs
    pub async fn submit_proof(
        &self,
        request_id: &str,
        proof: &[u8],
        public_inputs: &[u8],
    ) -> Result<VerificationResult, crate::errors::CollectorError> {
        let request_id_bytes: FixedBytes<32> = request_id
            .parse()
            .map_err(|e: <FixedBytes<32> as core::str::FromStr>::Err| {
                crate::errors::CollectorError::L1Error(format!(
                    "invalid request_id hex: {e}"
                ))
            })?;

        let coordinator =
            ICoordinator::new(self.coordinator_address, &self.provider);

        debug!(
            request_id = %request_id,
            proof_len = proof.len(),
            public_inputs_len = public_inputs.len(),
            "Submitting proof to Coordinator"
        );

        // Build and send the transaction.
        let tx_builder = coordinator
            .submitProof(
                request_id_bytes,
                Bytes::copy_from_slice(proof),
                Bytes::copy_from_slice(public_inputs),
            )
            .gas(self.gas_limit);

        let pending_tx = tx_builder.send().await.map_err(|e| {
            crate::errors::CollectorError::L1Error(format!(
                "failed to send submitProof tx: {e}"
            ))
        })?;

        let tx_hash = format!("0x{}", hex::encode(pending_tx.tx_hash().as_slice()));
        info!(tx_hash = %tx_hash, "Transaction sent, waiting for receipt");

        // Wait for confirmation.
        let receipt = pending_tx
            .get_receipt()
            .await
            .map_err(|e| {
                crate::errors::CollectorError::L1Error(format!(
                    "failed to get receipt: {e}"
                ))
            })?;

        // Check transaction status.
        if !receipt.status() {
            return Err(crate::errors::CollectorError::VerificationFailed(
                format!("transaction reverted: {tx_hash}"),
            ));
        }

        let gas_used = receipt.gas_used as u64;

        // Parse ProofVerified event from receipt logs.
        let event = receipt
            .inner
            .logs()
            .iter()
            .find_map(|log| {
                log.log_decode::<ICoordinator::ProofVerified>().ok()
            })
            .ok_or(crate::errors::CollectorError::EventNotFound)?;

        let proof_id = format!("0x{}", hex::encode(event.inner.data.proofId.as_slice()));
        let circuit_id = format!("0x{}", hex::encode(event.inner.data.circuitId.as_slice()));
        let timestamp = event.inner.data.timestamp;

        info!(
            tx_hash = %tx_hash,
            gas_used = gas_used,
            proof_id = %proof_id,
            "Proof verified on L1"
        );

        Ok(VerificationResult {
            tx_hash,
            gas_used,
            proof_id,
            circuit_id,
            timestamp: timestamp.to::<u64>(),
        })
    }

    /// Returns the coordinator contract address.
    pub fn coordinator_address(&self) -> Address {
        self.coordinator_address
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_result_fields() {
        let result = VerificationResult {
            tx_hash: "0xabc123".to_string(),
            gas_used: 30_000,
            proof_id: "0xdef456".to_string(),
            circuit_id: "0x789".to_string(),
            timestamp: 1700000000,
        };

        assert_eq!(result.tx_hash, "0xabc123");
        assert_eq!(result.gas_used, 30_000);
        assert_eq!(result.proof_id, "0xdef456");
    }

    #[test]
    fn test_l1_verifier_new_rejects_bad_url() {
        let config = CollectorConfig {
            l1_rpc_url: "not-a-url".to_string(),
            signer_private_key: "0x0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            coordinator_address: "0x0000000000000000000000000000000000000001".to_string(),
            ..CollectorConfig::default()
        };

        let result = L1Verifier::new(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_l1_verifier_new_rejects_bad_key() {
        let config = CollectorConfig {
            l1_rpc_url: "http://localhost:9650/ext/bc/sincerin/rpc".to_string(),
            signer_private_key: "not-a-key".to_string(),
            coordinator_address: "0x0000000000000000000000000000000000000001".to_string(),
            ..CollectorConfig::default()
        };

        let result = L1Verifier::new(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_l1_verifier_new_success() {
        let config = CollectorConfig {
            l1_rpc_url: "http://localhost:9650/ext/bc/sincerin/rpc".to_string(),
            signer_private_key: "0x0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            coordinator_address: "0x0000000000000000000000000000000000000001".to_string(),
            registry_address: "0x0000000000000000000000000000000000000002".to_string(),
            ..CollectorConfig::default()
        };

        let verifier = L1Verifier::new(&config).expect("should create verifier");
        assert_eq!(
            verifier.coordinator_address(),
            "0x0000000000000000000000000000000000000001"
                .parse::<Address>()
                .unwrap()
        );
    }
}
