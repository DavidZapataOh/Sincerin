//! Sincerin Collector — binary entrypoint.
//!
//! Startup flow:
//! 1. Initialize tracing
//! 2. Load configuration from environment
//! 3. Connect to NATS and setup JetStream streams
//! 4. Initialize Prometheus metrics exporter
//! 5. Create L1Verifier (with signer)
//! 6. Create NATS consumers (result + client)
//! 7. Enter main loop: fetch → verify → register → ack

use std::time::Duration;

use tracing::{error, info};

use sincerin_common::config::init_tracing;
use sincerin_common::nats;

use sincerin_collector::collector::Collector;
use sincerin_collector::config::CollectorConfig;
use sincerin_collector::consumer::{ClientConsumer, ResultConsumer};
use sincerin_collector::l1_verifier::L1Verifier;

#[tokio::main]
async fn main() {
    init_tracing("info");
    info!("Starting Sincerin Collector");

    // 1. Load configuration.
    let config = CollectorConfig::from_env();
    info!(
        nats_url = %config.nats_url,
        l1_rpc = %config.l1_rpc_url,
        coordinator = %config.coordinator_address,
        registry = %config.registry_address,
        consumer = %config.consumer_name,
        client_consumer = %config.client_consumer_name,
        gas_limit = config.gas_limit_submit,
        max_retries = config.max_retries,
        "Configuration loaded"
    );

    // 2. Connect to NATS.
    let client = match nats::connect(&config.nats_url).await {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "Failed to connect to NATS");
            std::process::exit(1);
        }
    };

    // 3. Setup JetStream streams (idempotent).
    if let Err(e) = nats::setup_streams(&client).await {
        error!(error = %e, "Failed to setup NATS streams");
        std::process::exit(1);
    }

    let js = nats::jetstream_context(&client);

    // 4. Initialize metrics.
    if let Err(e) = sincerin_common::metrics::init_metrics_exporter(config.metrics_port) {
        error!(error = %e, "Failed to start metrics exporter (non-fatal)");
    }

    // 5. Create L1Verifier.
    let verifier = match L1Verifier::new(&config) {
        Ok(v) => v,
        Err(e) => {
            error!(error = %e, "Failed to create L1Verifier");
            std::process::exit(1);
        }
    };

    // 6. Create NATS consumers.
    let result_consumer = match ResultConsumer::new(js.clone(), config.clone()).await {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "Failed to create result consumer");
            std::process::exit(1);
        }
    };

    let client_consumer = match ClientConsumer::new(js.clone(), config.clone()).await {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "Failed to create client consumer");
            std::process::exit(1);
        }
    };

    let collector = Collector::new(verifier, js, config);

    info!("Collector ready — entering main loop");

    // 7. Main loop: alternate between result and client streams.
    loop {
        // Process prover results.
        match result_consumer.fetch_batch().await {
            Ok(batch) => {
                if !batch.is_empty() {
                    info!(batch_size = batch.len(), source = "prover", "Fetched batch");
                }
                for (result, handle) in batch {
                    collector.process_proof(result, handle, "prover").await;
                }
            }
            Err(e) => {
                error!(error = %e, "Error fetching prover results — will retry");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }

        // Process client-side proofs.
        match client_consumer.fetch_batch().await {
            Ok(batch) => {
                if !batch.is_empty() {
                    info!(batch_size = batch.len(), source = "client", "Fetched batch");
                }
                for (result, handle) in batch {
                    collector.process_proof(result, handle, "client").await;
                }
            }
            Err(e) => {
                error!(error = %e, "Error fetching client proofs — will retry");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}
