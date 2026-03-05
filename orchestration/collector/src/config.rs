//! Collector-specific configuration.
//!
//! Extends the common configuration with collector-specific settings:
//! NATS consumer names, gas limits for L1 transactions, retry policy,
//! and the signer private key for submitting proofs on-chain.

use serde::Deserialize;

// -- Default value functions --------------------------------------------------

fn default_nats_url() -> String {
    "nats://localhost:4222".to_string()
}

fn default_l1_rpc_url() -> String {
    "http://localhost:9650/ext/bc/sincerin/rpc".to_string()
}

fn default_consumer_name() -> String {
    "collector-results".to_string()
}

fn default_client_consumer_name() -> String {
    "collector-client".to_string()
}

fn default_gas_limit_submit() -> u64 {
    100_000
}

fn default_metrics_port() -> u16 {
    9093
}

fn default_max_retries() -> u32 {
    3
}

fn default_retry_delay_ms() -> u64 {
    1000
}

fn default_chain_id() -> u64 {
    43214321
}

// -- CollectorConfig ----------------------------------------------------------

/// Configuration for the Sincerin Collector service.
#[derive(Debug, Clone, Deserialize)]
pub struct CollectorConfig {
    /// NATS server URL.
    #[serde(default = "default_nats_url")]
    pub nats_url: String,

    /// L1 HTTP RPC URL for submitting transactions.
    #[serde(default = "default_l1_rpc_url")]
    pub l1_rpc_url: String,

    /// Coordinator contract address on the L1 (hex, 0x-prefixed).
    pub coordinator_address: String,

    /// ProofRegistry contract address on the L1 (hex, 0x-prefixed).
    pub registry_address: String,

    /// Private key for signing L1 transactions (hex, 0x-prefixed).
    /// Required — the collector must submit proofs on-chain.
    pub signer_private_key: String,

    /// Durable consumer name for proof results from provers.
    #[serde(default = "default_consumer_name")]
    pub consumer_name: String,

    /// Durable consumer name for client-side proofs.
    #[serde(default = "default_client_consumer_name")]
    pub client_consumer_name: String,

    /// Gas limit for Coordinator.submitProof() transactions.
    /// Expected usage ~30K, safety margin at 100K.
    #[serde(default = "default_gas_limit_submit")]
    pub gas_limit_submit: u64,

    /// Prometheus metrics exporter port.
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,

    /// Maximum retry attempts for retryable L1 errors.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Base delay between retries in milliseconds (doubles each retry).
    #[serde(default = "default_retry_delay_ms")]
    pub retry_delay_ms: u64,

    /// Chain ID for the Sincerin L1 (must match genesis).
    #[serde(default = "default_chain_id")]
    pub chain_id: u64,
}

impl CollectorConfig {
    /// Load configuration from environment variables with prefix `SINCERIN_COLLECTOR_`.
    ///
    /// Falls back to defaults for optional fields. Required fields
    /// (`coordinator_address`, `registry_address`, `signer_private_key`)
    /// must be set or the function returns an error.
    pub fn from_env() -> Self {
        let settings = config::Config::builder()
            .add_source(
                config::Environment::with_prefix("SINCERIN_COLLECTOR").try_parsing(true),
            )
            .build()
            .expect("failed to build config from env");

        settings
            .try_deserialize()
            .expect("failed to deserialize CollectorConfig — check required env vars")
    }
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            nats_url: default_nats_url(),
            l1_rpc_url: default_l1_rpc_url(),
            coordinator_address: String::new(),
            registry_address: String::new(),
            signer_private_key: String::new(),
            consumer_name: default_consumer_name(),
            client_consumer_name: default_client_consumer_name(),
            gas_limit_submit: default_gas_limit_submit(),
            metrics_port: default_metrics_port(),
            max_retries: default_max_retries(),
            retry_delay_ms: default_retry_delay_ms(),
            chain_id: default_chain_id(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = CollectorConfig::default();

        assert_eq!(config.nats_url, "nats://localhost:4222");
        assert_eq!(
            config.l1_rpc_url,
            "http://localhost:9650/ext/bc/sincerin/rpc"
        );
        assert_eq!(config.consumer_name, "collector-results");
        assert_eq!(config.client_consumer_name, "collector-client");
        assert_eq!(config.gas_limit_submit, 100_000);
        assert_eq!(config.metrics_port, 9093);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_delay_ms, 1000);
        assert_eq!(config.chain_id, 43214321);
    }

    #[test]
    fn test_config_required_fields_are_empty_by_default() {
        let config = CollectorConfig::default();
        assert!(config.coordinator_address.is_empty());
        assert!(config.registry_address.is_empty());
        assert!(config.signer_private_key.is_empty());
    }
}
