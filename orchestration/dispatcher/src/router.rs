use async_nats::jetstream::Context as JetStream;
use serde::{Deserialize, Serialize};
use tracing::info;

use sincerin_common::nats;
use sincerin_common::types::{PrivacyStrategy, ProofRequest, ProofStatus};

use crate::errors::DispatcherError;

/// A task assigned to a prover node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverTask {
    pub request_id: String,
    pub circuit_id: String,
    pub strategy: PrivacyStrategy,
    pub split_data: Option<serde_json::Value>,
    pub public_inputs: serde_json::Value,
    pub deadline: u64,
    pub assigned_at: String,
    pub prover_id: String,
}

/// Routes proof requests to the appropriate prover based on strategy.
pub struct Router {
    default_prover_id: String,
}

impl Router {
    pub fn new(default_prover_id: String) -> Self {
        Self { default_prover_id }
    }

    /// Route a proof request to the appropriate destination based on strategy.
    ///
    /// - ClientSide → publish to `sincerin.proofs.client`, status = AwaitingClientProof
    /// - DirectDelegation / StructuralSplit → publish ProverTask to
    ///   `sincerin.proofs.tasks.<prover_id>`, status = Assigned
    pub async fn route_request(
        &self,
        request: &ProofRequest,
        strategy: &PrivacyStrategy,
        js: &JetStream,
    ) -> Result<(), DispatcherError> {
        let now = chrono::Utc::now().to_rfc3339();

        match strategy {
            PrivacyStrategy::ClientSide => {
                // Client-side proving: don't send to a prover.
                // Publish back to a client subject so the Collector can handle it.
                nats::publish(js, "sincerin.proofs.client", request)
                    .await
                    .map_err(|e| DispatcherError::PublishFailed(e.to_string()))?;

                // Publish status update: awaiting client proof
                let status = ProofStatus::ClientComputing;
                nats::publish_status_update(js, &request.request_id, &status)
                    .await
                    .map_err(|e| DispatcherError::PublishFailed(e.to_string()))?;

                info!(
                    request_id = %request.request_id,
                    strategy = "client_side",
                    "Routed to client (no prover needed)"
                );
            }
            _ => {
                // DirectDelegation, StructuralSplit, or any other strategy:
                // Send task to the prover.
                let prover_id = &self.default_prover_id;

                let task = ProverTask {
                    request_id: request.request_id.clone(),
                    circuit_id: request.circuit_id.clone(),
                    strategy: strategy.clone(),
                    split_data: None, // Will be populated when split proving is implemented
                    public_inputs: request.public_inputs.clone(),
                    deadline: request.deadline,
                    assigned_at: now,
                    prover_id: prover_id.clone(),
                };

                let task_subject = format!("sincerin.proofs.tasks.{prover_id}");
                nats::publish(js, &task_subject, &task)
                    .await
                    .map_err(|e| DispatcherError::PublishFailed(e.to_string()))?;

                // Publish status update: assigned
                let status = ProofStatus::Assigned {
                    prover_id: prover_id.clone(),
                };
                nats::publish_status_update(js, &request.request_id, &status)
                    .await
                    .map_err(|e| DispatcherError::PublishFailed(e.to_string()))?;

                info!(
                    request_id = %request.request_id,
                    prover_id = %prover_id,
                    strategy = ?strategy,
                    "Routed to prover"
                );
            }
        }

        metrics::counter!("sincerin_dispatcher_tasks_routed_total",
            "prover_id" => if matches!(strategy, PrivacyStrategy::ClientSide) {
                "client".to_string()
            } else {
                self.default_prover_id.clone()
            },
            "strategy" => format!("{strategy:?}")
        )
        .increment(1);

        Ok(())
    }
}
