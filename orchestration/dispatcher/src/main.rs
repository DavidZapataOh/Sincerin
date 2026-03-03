use std::time::Instant;

use tracing::{error, info};

use sincerin_common::config::init_tracing;
use sincerin_common::nats;

use sincerin_dispatcher::config::DispatcherConfig;
use sincerin_dispatcher::consumer::RequestConsumer;
use sincerin_dispatcher::priority::PriorityQueue;
use sincerin_dispatcher::router::Router;
use sincerin_dispatcher::strategy::{CircuitRegistry, StrategySelector};

#[tokio::main]
async fn main() {
    init_tracing("info");
    info!("Starting Sincerin Dispatcher");

    let config = DispatcherConfig::from_env();
    info!(
        nats_url = %config.nats_url,
        consumer = %config.consumer_name,
        batch_size = config.batch_size,
        prover_id = %config.default_prover_id,
        "Configuration loaded"
    );

    // Connect to NATS
    let client = match nats::connect(&config.nats_url).await {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "Failed to connect to NATS");
            std::process::exit(1);
        }
    };

    // Setup streams (idempotent)
    if let Err(e) = nats::setup_streams(&client).await {
        error!(error = %e, "Failed to setup NATS streams");
        std::process::exit(1);
    }

    let js = nats::jetstream_context(&client);

    // Initialize metrics
    if let Err(e) = sincerin_common::metrics::init_metrics_exporter(config.metrics_port) {
        error!(error = %e, "Failed to start metrics exporter (non-fatal)");
    }

    // Build dispatcher components
    let consumer = match RequestConsumer::new(js.clone(), config.clone()).await {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "Failed to create NATS consumer");
            std::process::exit(1);
        }
    };

    let strategy_selector = StrategySelector::new(CircuitRegistry::new());
    let router = Router::new(config.default_prover_id.clone());
    let mut priority_queue = PriorityQueue::new(config.queue_max_size);

    info!("Dispatcher ready — entering main loop");

    // Main dispatch loop
    loop {
        // 1. Fetch batch from NATS
        let batch = match consumer.fetch_batch().await {
            Ok(b) => b,
            Err(e) => {
                error!(error = %e, "Error fetching batch — will retry");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };

        if batch.is_empty() {
            continue;
        }

        info!(batch_size = batch.len(), "Fetched batch");

        // 2. Insert into priority queue
        for (request, ack_handle) in batch {
            priority_queue.push(request.clone(), 0);

            // Process immediately from queue (hybrid approach per plan)
            let start = Instant::now();
            match process_request(&request, &strategy_selector, &router, &js).await {
                Ok(()) => {
                    if let Err(e) = ack_handle.ack().await {
                        error!(error = %e, "Failed to ack message");
                    }
                    let elapsed = start.elapsed();
                    metrics::histogram!("sincerin_dispatcher_dispatch_latency_seconds")
                        .record(elapsed.as_secs_f64());
                    sincerin_common::metrics::record_orchestration_latency(elapsed.as_secs_f64());
                    info!(
                        request_id = %request.request_id,
                        elapsed_ms = elapsed.as_millis(),
                        "Dispatched successfully"
                    );
                }
                Err(e) if e.is_retryable() => {
                    error!(error = %e, request_id = %request.request_id, "Retryable error — nacking");
                    if let Err(nack_err) = ack_handle.nack().await {
                        error!(error = %nack_err, "Failed to nack message");
                    }
                    metrics::counter!("sincerin_dispatcher_retries_total").increment(1);
                }
                Err(e) => {
                    error!(error = %e, request_id = %request.request_id, "Non-retryable error — acking");
                    if let Err(ack_err) = ack_handle.ack().await {
                        error!(error = %ack_err, "Failed to ack message after error");
                    }
                    metrics::counter!("sincerin_dispatcher_failures_total").increment(1);
                }
            }

            // Pop from priority queue (keep it synchronized)
            priority_queue.pop();
        }

        // Report queue depth
        metrics::gauge!("sincerin_dispatcher_queue_depth").set(priority_queue.len() as f64);
    }
}

async fn process_request(
    request: &sincerin_common::types::ProofRequest,
    strategy_selector: &StrategySelector,
    router: &Router,
    js: &async_nats::jetstream::Context,
) -> Result<(), sincerin_dispatcher::errors::DispatcherError> {
    let strategy = strategy_selector.select(request)?;
    router.route_request(request, &strategy, js).await
}
