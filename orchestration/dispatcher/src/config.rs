use serde::Deserialize;

fn default_nats_url() -> String {
    "nats://localhost:4222".to_string()
}

fn default_consumer_name() -> String {
    "dispatcher".to_string()
}

fn default_batch_size() -> usize {
    10
}

fn default_batch_wait_ms() -> u64 {
    100
}

fn default_max_retries() -> u32 {
    3
}

fn default_metrics_port() -> u16 {
    9091
}

fn default_prover_id() -> String {
    "prover-01".to_string()
}

fn default_queue_max_size() -> usize {
    10_000
}

/// Configuration for the Dispatcher service.
#[derive(Debug, Clone, Deserialize)]
pub struct DispatcherConfig {
    /// NATS server URL.
    #[serde(default = "default_nats_url")]
    pub nats_url: String,

    /// Durable consumer name on the PROOF_REQUESTS stream.
    #[serde(default = "default_consumer_name")]
    pub consumer_name: String,

    /// Maximum messages to pull per batch.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Maximum wait time (ms) for a batch to fill before processing.
    #[serde(default = "default_batch_wait_ms")]
    pub batch_wait_ms: u64,

    /// Maximum delivery attempts before a message is discarded.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Port for the Prometheus metrics exporter.
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,

    /// Default prover ID for MVP single-prover routing.
    #[serde(default = "default_prover_id")]
    pub default_prover_id: String,

    /// Maximum size of the priority queue.
    #[serde(default = "default_queue_max_size")]
    pub queue_max_size: usize,
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            nats_url: default_nats_url(),
            consumer_name: default_consumer_name(),
            batch_size: default_batch_size(),
            batch_wait_ms: default_batch_wait_ms(),
            max_retries: default_max_retries(),
            metrics_port: default_metrics_port(),
            default_prover_id: default_prover_id(),
            queue_max_size: default_queue_max_size(),
        }
    }
}

impl DispatcherConfig {
    /// Load configuration from environment variables prefixed with
    /// `SINCERIN_DISPATCHER_`.
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(v) = std::env::var("SINCERIN_DISPATCHER_NATS_URL") {
            config.nats_url = v;
        }
        if let Ok(v) = std::env::var("SINCERIN_DISPATCHER_CONSUMER_NAME") {
            config.consumer_name = v;
        }
        if let Ok(v) = std::env::var("SINCERIN_DISPATCHER_BATCH_SIZE")
            && let Ok(n) = v.parse()
        {
            config.batch_size = n;
        }
        if let Ok(v) = std::env::var("SINCERIN_DISPATCHER_BATCH_WAIT_MS")
            && let Ok(n) = v.parse()
        {
            config.batch_wait_ms = n;
        }
        if let Ok(v) = std::env::var("SINCERIN_DISPATCHER_MAX_RETRIES")
            && let Ok(n) = v.parse()
        {
            config.max_retries = n;
        }
        if let Ok(v) = std::env::var("SINCERIN_DISPATCHER_METRICS_PORT")
            && let Ok(n) = v.parse()
        {
            config.metrics_port = n;
        }
        if let Ok(v) = std::env::var("SINCERIN_DISPATCHER_PROVER_ID") {
            config.default_prover_id = v;
        }
        if let Ok(v) = std::env::var("SINCERIN_DISPATCHER_QUEUE_MAX_SIZE")
            && let Ok(n) = v.parse()
        {
            config.queue_max_size = n;
        }

        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = DispatcherConfig::default();
        assert_eq!(config.nats_url, "nats://localhost:4222");
        assert_eq!(config.consumer_name, "dispatcher");
        assert_eq!(config.batch_size, 10);
        assert_eq!(config.batch_wait_ms, 100);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.metrics_port, 9091);
        assert_eq!(config.default_prover_id, "prover-01");
        assert_eq!(config.queue_max_size, 10_000);
    }

    #[test]
    fn test_config_from_env() {
        // Use unsafe because Rust 2024 requires it for set_var
        unsafe {
            std::env::set_var("SINCERIN_DISPATCHER_BATCH_SIZE", "50");
            std::env::set_var("SINCERIN_DISPATCHER_PROVER_ID", "prover-99");
        }

        let config = DispatcherConfig::from_env();
        assert_eq!(config.batch_size, 50);
        assert_eq!(config.default_prover_id, "prover-99");

        // Clean up
        unsafe {
            std::env::remove_var("SINCERIN_DISPATCHER_BATCH_SIZE");
            std::env::remove_var("SINCERIN_DISPATCHER_PROVER_ID");
        }
    }
}
