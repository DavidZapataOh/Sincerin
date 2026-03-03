use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio_util::sync::CancellationToken;
use tracing::info;
use tracing_subscriber::EnvFilter;

use sincerin_common::nats;
use sincerin_prover_node::backends::barretenberg::BarretenbergBackend;
use sincerin_prover_node::config::ProverConfig;
use sincerin_prover_node::consumer::TaskConsumer;
use sincerin_prover_node::executor::Executor;
use sincerin_prover_node::heartbeat::{HeartbeatService, SharedState};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = ProverConfig::from_env();
    info!(
        prover_id = %config.prover_id,
        nats_url = %config.nats_url,
        bb_path = %config.bb_binary_path.display(),
        circuits_dir = %config.circuits_dir.display(),
        "Starting Sincerin Prover Node"
    );

    // Connect to NATS and ensure streams exist
    let client = nats::connect(&config.nats_url).await?;
    nats::setup_streams(&client).await?;
    let js = nats::jetstream_context(&client);

    // Create the Barretenberg backend
    let backend = BarretenbergBackend::new(
        config.bb_binary_path.clone(),
        config.circuits_dir.clone(),
        config.work_dir.clone(),
    )?;

    // Shared state for heartbeat <-> executor communication
    let shared_state = Arc::new(SharedState::new());

    // Create executor
    let executor = Arc::new(Executor::new(
        Arc::new(backend),
        config.prover_id.clone(),
    ));

    // Cancellation token for graceful shutdown
    let cancel = CancellationToken::new();

    // Start heartbeat service
    let heartbeat = HeartbeatService::new(
        js.clone(),
        config.prover_id.clone(),
        Duration::from_secs(config.heartbeat_interval_secs),
        shared_state.clone(),
        config.max_concurrent_proofs as u32,
    );
    let heartbeat_cancel = cancel.clone();
    tokio::spawn(async move {
        heartbeat.run(heartbeat_cancel).await;
    });

    // Start task consumer
    let consumer = TaskConsumer::new(js.clone(), executor, config.clone());
    let consumer_cancel = cancel.clone();
    let consumer_handle = tokio::spawn(async move {
        if let Err(e) = consumer.run(consumer_cancel).await {
            tracing::error!(error = %e, "Task consumer exited with error");
        }
    });

    // Wait for shutdown signal
    info!("Prover node running. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;
    info!("Shutdown signal received, draining...");

    // Signal all tasks to stop
    cancel.cancel();

    // Wait for consumer to finish current work
    let _ = tokio::time::timeout(Duration::from_secs(30), consumer_handle).await;

    info!("Prover node shut down cleanly");
    Ok(())
}
