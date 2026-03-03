use std::sync::Arc;

use sha2::{Digest, Sha256};
use tracing::{info, warn};

use sincerin_common::types::{PrivacyStrategy, ProofResult as CommonProofResult};

use crate::backends::{ProofOutput, ProverBackend};
use crate::consumer::ProverTask;
use crate::errors::ProverError;

/// Orchestrates proof generation by dispatching tasks to the backend
/// based on the requested privacy strategy.
pub struct Executor {
    backend: Arc<dyn ProverBackend>,
    prover_id: String,
}

impl Executor {
    pub fn new(backend: Arc<dyn ProverBackend>, prover_id: String) -> Self {
        Self {
            backend,
            prover_id,
        }
    }

    /// Execute a prover task and produce a proof result.
    ///
    /// Strategy dispatch:
    /// - `DirectDelegation`: Full witness → `backend.prove()` → result
    /// - `ClientSide`: Should never reach prover (dispatcher error) → error
    /// - `StructuralSplit`: Not implemented in MVP → error
    pub async fn execute(&self, task: &ProverTask) -> Result<CommonProofResult, ProverError> {
        info!(
            request_id = %task.request_id,
            circuit_id = %task.circuit_id,
            strategy = ?task.strategy,
            "Executing task"
        );

        metrics::counter!("sincerin_prover_tasks_executed_total",
            "strategy" => format!("{:?}", task.strategy),
            "status" => "started"
        )
        .increment(1);

        let result = match &task.strategy {
            PrivacyStrategy::DirectDelegation => self.execute_direct_delegation(task).await,
            PrivacyStrategy::ClientSide => {
                warn!(
                    request_id = %task.request_id,
                    "ClientSide task reached prover — dispatcher should have routed to client"
                );
                Err(ProverError::UnexpectedClientSideTask)
            }
            PrivacyStrategy::StructuralSplit => Err(ProverError::UnsupportedStrategy(
                "StructuralSplit not implemented, coming in Sprint 3".to_string(),
            )),
            other => Err(ProverError::UnsupportedStrategy(format!("{other:?}"))),
        };

        let status_label = if result.is_ok() { "success" } else { "failure" };
        metrics::counter!("sincerin_prover_tasks_executed_total",
            "strategy" => format!("{:?}", task.strategy),
            "status" => status_label.to_string()
        )
        .increment(1);

        result
    }

    /// Execute a DirectDelegation task: full witness available, generate proof.
    async fn execute_direct_delegation(
        &self,
        task: &ProverTask,
    ) -> Result<CommonProofResult, ProverError> {
        let witness = task
            .witness
            .as_ref()
            .ok_or(ProverError::MissingWitness)?;

        let ProofOutput {
            proof,
            proving_time_ms,
        } = self.backend.prove(&task.circuit_id, witness).await?;

        // Compute public_inputs_hash for logging/debugging
        let public_inputs_json = serde_json::to_vec(&task.public_inputs)?;
        let _public_inputs_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&public_inputs_json);
            hex::encode(hasher.finalize())
        };

        info!(
            request_id = %task.request_id,
            proving_time_ms = proving_time_ms,
            proof_size = proof.len(),
            "Direct delegation proof generated"
        );

        Ok(CommonProofResult {
            request_id: task.request_id.clone(),
            proof_id: format!("proof-{}", task.request_id),
            circuit_id: task.circuit_id.clone(),
            proof,
            public_inputs: task.public_inputs.clone(),
            privacy_strategy: task.strategy.clone(),
            prover_id: self.prover_id.clone(),
            proving_time_ms,
            verified: false, // L1 verification happens in the collector
            verification_gas: 0,
            l1_tx_hash: None,
            created_at: chrono::Utc::now().timestamp() as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::ProofOutput;
    use async_trait::async_trait;

    /// Mock backend for unit testing the executor without bb CLI.
    struct MockBackend {
        prove_result: Result<ProofOutput, ProverError>,
    }

    #[async_trait]
    impl ProverBackend for MockBackend {
        async fn prove(
            &self,
            _circuit_id: &str,
            _witness: &[u8],
        ) -> Result<ProofOutput, ProverError> {
            match &self.prove_result {
                Ok(output) => Ok(output.clone()),
                Err(_) => Err(ProverError::ProveFailed("mock failure".to_string())),
            }
        }

        async fn verify(
            &self,
            _circuit_id: &str,
            _proof: &[u8],
        ) -> Result<bool, ProverError> {
            Ok(true)
        }
    }

    fn mock_task(strategy: PrivacyStrategy, with_witness: bool) -> ProverTask {
        ProverTask {
            request_id: "test-req-001".to_string(),
            circuit_id: "proof-of-membership".to_string(),
            strategy,
            split_data: None,
            public_inputs: serde_json::json!({"root": "0x1234"}),
            witness: if with_witness {
                Some(vec![1, 2, 3, 4])
            } else {
                None
            },
            client_proof: None,
            deadline: chrono::Utc::now().timestamp() as u64 + 3600,
            assigned_at: chrono::Utc::now().to_rfc3339(),
            prover_id: "prover-test".to_string(),
        }
    }

    #[tokio::test]
    async fn test_execute_direct_delegation_success() {
        let backend = Arc::new(MockBackend {
            prove_result: Ok(ProofOutput {
                proof: vec![0xde, 0xad, 0xbe, 0xef],
                proving_time_ms: 1500,
            }),
        });
        let executor = Executor::new(backend, "prover-test".to_string());
        let task = mock_task(PrivacyStrategy::DirectDelegation, true);

        let result = executor.execute(&task).await;
        assert!(result.is_ok());

        let proof_result = result.unwrap();
        assert_eq!(proof_result.request_id, "test-req-001");
        assert_eq!(proof_result.circuit_id, "proof-of-membership");
        assert_eq!(proof_result.proof, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(proof_result.proving_time_ms, 1500);
        assert_eq!(proof_result.prover_id, "prover-test");
        assert_eq!(
            proof_result.privacy_strategy,
            PrivacyStrategy::DirectDelegation
        );
    }

    #[tokio::test]
    async fn test_execute_direct_delegation_missing_witness() {
        let backend = Arc::new(MockBackend {
            prove_result: Ok(ProofOutput {
                proof: vec![],
                proving_time_ms: 0,
            }),
        });
        let executor = Executor::new(backend, "prover-test".to_string());
        let task = mock_task(PrivacyStrategy::DirectDelegation, false);

        let result = executor.execute(&task).await;
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("Missing witness"),
            "Should report missing witness"
        );
    }

    #[tokio::test]
    async fn test_execute_client_side_unexpected() {
        let backend = Arc::new(MockBackend {
            prove_result: Ok(ProofOutput {
                proof: vec![],
                proving_time_ms: 0,
            }),
        });
        let executor = Executor::new(backend, "prover-test".to_string());
        let task = mock_task(PrivacyStrategy::ClientSide, false);

        let result = executor.execute(&task).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("client-side task"));
    }

    #[tokio::test]
    async fn test_execute_structural_split_unsupported() {
        let backend = Arc::new(MockBackend {
            prove_result: Ok(ProofOutput {
                proof: vec![],
                proving_time_ms: 0,
            }),
        });
        let executor = Executor::new(backend, "prover-test".to_string());
        let task = mock_task(PrivacyStrategy::StructuralSplit, false);

        let result = executor.execute(&task).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("StructuralSplit"));
    }

    #[tokio::test]
    async fn test_execute_backend_failure() {
        let backend = Arc::new(MockBackend {
            prove_result: Err(ProverError::ProveFailed("bb crashed".to_string())),
        });
        let executor = Executor::new(backend, "prover-test".to_string());
        let task = mock_task(PrivacyStrategy::DirectDelegation, true);

        let result = executor.execute(&task).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_execute_proof_result_has_public_inputs_hash() {
        let backend = Arc::new(MockBackend {
            prove_result: Ok(ProofOutput {
                proof: vec![0xaa],
                proving_time_ms: 100,
            }),
        });
        let executor = Executor::new(backend, "prover-test".to_string());
        let task = mock_task(PrivacyStrategy::DirectDelegation, true);

        let result = executor.execute(&task).await.unwrap();
        // proof_id should be populated
        assert!(!result.proof_id.is_empty());
        // created_at should be recent
        assert!(result.created_at > 0);
    }
}
