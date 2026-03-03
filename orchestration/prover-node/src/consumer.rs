use std::sync::Arc;
use std::time::Duration;

use async_nats::jetstream::consumer::pull::Config as PullConfig;
use async_nats::jetstream::Context as JetStream;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use sincerin_common::nats;
use sincerin_common::types::{PrivacyStrategy, ProofStatus};

use crate::config::ProverConfig;
use crate::errors::ProverError;
use crate::executor::Executor;

/// A task assigned to a prover node by the dispatcher.
///
/// This is the input format consumed from NATS. The `witness` and
/// `client_proof` fields are optional — they default to `None` when
/// absent from the JSON payload (for backwards compatibility with
/// the dispatcher's current ProverTask format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverTask {
    pub request_id: String,
    pub circuit_id: String,
    pub strategy: PrivacyStrategy,
    #[serde(default)]
    pub split_data: Option<serde_json::Value>,
    pub public_inputs: serde_json::Value,
    #[serde(default)]
    pub witness: Option<Vec<u8>>,
    #[serde(default)]
    pub client_proof: Option<Vec<u8>>,
    pub deadline: u64,
    pub assigned_at: String,
    pub prover_id: String,
}

/// NATS consumer that pulls prover tasks and drives the executor.
pub struct TaskConsumer {
    js: JetStream,
    executor: Arc<Executor>,
    config: ProverConfig,
}

impl TaskConsumer {
    pub fn new(js: JetStream, executor: Arc<Executor>, config: ProverConfig) -> Self {
        Self {
            js,
            executor,
            config,
        }
    }

    /// Run the main consume-execute-publish loop until cancellation.
    pub async fn run(&self, cancel: CancellationToken) -> Result<(), ProverError> {
        let filter_subject = format!(
            "{}.{}",
            nats::subjects::PROOF_TASKS,
            self.config.prover_id
        );

        info!(
            prover_id = %self.config.prover_id,
            filter_subject = %filter_subject,
            "Starting task consumer"
        );

        // Create a durable pull consumer on the PROOF_TASKS stream
        let stream = self
            .js
            .get_stream("PROOF_TASKS")
            .await
            .map_err(|e| ProverError::Nats(e.to_string()))?;

        let consumer_name = format!("prover-{}", self.config.prover_id);
        stream
            .get_or_create_consumer(
                &consumer_name,
                PullConfig {
                    durable_name: Some(consumer_name.clone()),
                    filter_subject: filter_subject.clone(),
                    ack_wait: Duration::from_secs(120), // Proof gen can be slow
                    max_deliver: 3,
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| ProverError::Nats(e.to_string()))?;

        let consumer = stream
            .get_consumer::<PullConfig>(&consumer_name)
            .await
            .map_err(|e| ProverError::Nats(e.to_string()))?;

        info!(consumer_name = %consumer_name, "Durable consumer ready");

        loop {
            if cancel.is_cancelled() {
                info!("Cancellation received, stopping consumer loop");
                break;
            }

            // Fetch one task at a time (MVP: sequential proving)
            let mut messages = consumer
                .fetch()
                .max_messages(1)
                .expires(Duration::from_millis(500))
                .messages()
                .await
                .map_err(|e| ProverError::Nats(e.to_string()))?;

            while let Some(msg_result) = messages.next().await {
                let msg = match msg_result {
                    Ok(m) => m,
                    Err(e) => {
                        warn!(error = %e, "Failed to receive message");
                        continue;
                    }
                };

                // Deserialize the task
                let task: ProverTask = match serde_json::from_slice(&msg.payload) {
                    Ok(t) => t,
                    Err(e) => {
                        error!(error = %e, "Failed to deserialize ProverTask — acking to skip");
                        let _ = msg.ack().await;
                        continue;
                    }
                };

                info!(
                    request_id = %task.request_id,
                    circuit_id = %task.circuit_id,
                    strategy = ?task.strategy,
                    "Received task"
                );

                metrics::counter!("sincerin_prover_tasks_received_total").increment(1);
                metrics::gauge!("sincerin_prover_current_task").set(1.0);

                // Publish status: Proving
                let proving_status = ProofStatus::Proving { progress: None };
                if let Err(e) =
                    nats::publish_status_update(&self.js, &task.request_id, &proving_status).await
                {
                    warn!(
                        request_id = %task.request_id,
                        error = %e,
                        "Failed to publish Proving status"
                    );
                }

                // Execute the task
                match self.executor.execute(&task).await {
                    Ok(result) => {
                        // Publish the result
                        if let Err(e) =
                            nats::publish(&self.js, nats::subjects::PROOF_RESULTS, &result).await
                        {
                            error!(
                                request_id = %task.request_id,
                                error = %e,
                                "Failed to publish ProofResult — nacking for retry"
                            );
                            let _ = msg
                                .ack_with(async_nats::jetstream::AckKind::Nak(None))
                                .await;
                            metrics::gauge!("sincerin_prover_current_task").set(0.0);
                            continue;
                        }

                        // Publish status: Verifying (proof generated, awaiting L1 verification)
                        let status = ProofStatus::Verifying;
                        let _ = nats::publish_status_update(
                            &self.js,
                            &task.request_id,
                            &status,
                        )
                        .await;

                        // Ack the task
                        if let Err(e) = msg.ack().await {
                            error!(
                                request_id = %task.request_id,
                                error = %e,
                                "Failed to ack task message"
                            );
                        }

                        metrics::counter!("sincerin_prover_tasks_completed_total",
                            "status" => "success"
                        )
                        .increment(1);

                        info!(
                            request_id = %task.request_id,
                            proving_time_ms = result.proving_time_ms,
                            "Task completed successfully"
                        );
                    }
                    Err(e) => {
                        error!(
                            request_id = %task.request_id,
                            error = %e,
                            "Task execution failed"
                        );

                        // Publish status: Failed
                        let status = ProofStatus::Failed {
                            reason: e.to_string(),
                            stage: "proving".to_string(),
                        };
                        let _ = nats::publish_status_update(
                            &self.js,
                            &task.request_id,
                            &status,
                        )
                        .await;

                        // Nack retryable, ack non-retryable
                        if e.is_retryable() {
                            let _ = msg
                                .ack_with(async_nats::jetstream::AckKind::Nak(None))
                                .await;
                        } else {
                            let _ = msg.ack().await;
                        }

                        metrics::counter!("sincerin_prover_tasks_completed_total",
                            "status" => "failure"
                        )
                        .increment(1);
                    }
                }

                metrics::gauge!("sincerin_prover_current_task").set(0.0);
            }
        }

        Ok(())
    }
}
