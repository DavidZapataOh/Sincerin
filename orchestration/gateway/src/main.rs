use sincerin_common::config::init_tracing;
use sincerin_common::nats;
use sincerin_gateway::config::GatewayConfig;
use sincerin_gateway::routes;
use sincerin_gateway::state::AppState;

#[tokio::main]
async fn main() {
    // Initialize tracing (structured JSON logging)
    init_tracing("info");

    tracing::info!("Starting Sincerin Gateway...");

    // Load configuration from environment
    let config = GatewayConfig::from_env();

    tracing::info!(
        host = %config.host,
        port = config.port,
        nats_url = %config.nats_url,
        api_keys_count = config.api_keys.len(),
        rate_limit_rps = config.rate_limit_rps,
        "Configuration loaded"
    );

    // Connect to NATS
    let nats_client = match nats::connect(&config.nats_url).await {
        Ok(client) => {
            tracing::info!("Connected to NATS");
            client
        }
        Err(e) => {
            tracing::error!("Failed to connect to NATS at {}: {e}", config.nats_url);
            tracing::warn!("Starting without NATS — requests will fail until NATS is available");
            // In production we'd retry; for MVP we exit gracefully
            std::process::exit(1);
        }
    };

    // Setup NATS streams (idempotent)
    if let Err(e) = nats::setup_streams(&nats_client).await {
        tracing::error!("Failed to setup NATS streams: {e}");
        std::process::exit(1);
    }
    tracing::info!("NATS streams configured");

    let jetstream = nats::jetstream_context(&nats_client);

    // Initialize metrics exporter
    if let Err(e) = sincerin_common::metrics::init_metrics_exporter(config.metrics_port) {
        tracing::warn!("Failed to start metrics exporter on port {}: {e}", config.metrics_port);
    } else {
        tracing::info!("Metrics exporter started on port {}", config.metrics_port);
    }

    // Build application state
    let state = AppState::new(jetstream, config.clone());

    // Build router
    let app = routes::build_router(state);

    // Start rate limiter cleanup task
    let rate_limiter = AppState::new(
        nats::jetstream_context(&nats_client),
        config.clone(),
    )
    .rate_limiter;

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            rate_limiter.cleanup(tokio::time::Duration::from_secs(300));
        }
    });

    // Bind and serve
    let addr = format!("{}:{}", config.host, config.port);
    tracing::info!("Gateway listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind to address");

    axum::serve(listener, app)
        .await
        .expect("Server error");
}
