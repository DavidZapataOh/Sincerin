//! Shared configuration for all Sincerin orchestration services.
//!
//! Configuration is loaded using the `config` crate with three layers
//! (in ascending priority):
//!
//! 1. **Defaults** -- hardcoded sensible values for local development.
//! 2. **Config file** -- optional `sincerin.toml` / `sincerin.json` / etc.
//! 3. **Environment variables** -- prefixed with `SINCERIN_` (e.g.
//!    `SINCERIN_NATS_URL`), which override everything else.
//!
//! Design notes (Buterin): one config schema, one env prefix, one format.
//! Design notes (Drake): defaults are safe for local dev; production
//! always overrides via env vars in container orchestration.

use serde::Deserialize;
use tracing_subscriber::EnvFilter;

// ---------------------------------------------------------------------------
// Default value functions (used by serde)
// ---------------------------------------------------------------------------

fn default_nats_url() -> String {
    "nats://localhost:4222".to_string()
}

fn default_l1_rpc_url() -> String {
    "http://localhost:9650/ext/bc/sincerin/rpc".to_string()
}

fn default_l1_ws_url() -> String {
    "ws://localhost:9650/ext/bc/sincerin/ws".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_metrics_port() -> u16 {
    9090
}

fn default_chain_id() -> u64 {
    43214321
}

// ---------------------------------------------------------------------------
// CommonConfig
// ---------------------------------------------------------------------------

/// Shared configuration consumed by every orchestration service.
///
/// Services that need additional settings should embed `CommonConfig`
/// and add their own fields alongside it.
#[derive(Debug, Clone, Deserialize)]
pub struct CommonConfig {
    /// NATS server URL (e.g. `nats://nats:4222`).
    #[serde(default = "default_nats_url")]
    pub nats_url: String,

    /// HTTP RPC URL for the Sincerin L1 node.
    #[serde(default = "default_l1_rpc_url")]
    pub l1_rpc_url: String,

    /// WebSocket URL for the Sincerin L1 node.
    #[serde(default = "default_l1_ws_url")]
    pub l1_ws_url: String,

    /// Address of the Coordinator contract on the L1.
    pub coordinator_address: String,

    /// Address of the ProofRegistry contract on the L1.
    pub proof_registry_address: String,

    /// Address of the ProverRegistry contract on the L1.
    pub prover_registry_address: String,

    /// Log level filter (e.g. `info`, `debug`, `warn`).
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Port for the Prometheus metrics HTTP exporter.
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,

    /// Chain ID for the Sincerin L1 (must match genesis).
    #[serde(default = "default_chain_id")]
    pub chain_id: u64,
}

impl CommonConfig {
    /// Load configuration from defaults, optional config file, and
    /// environment variables.
    ///
    /// Layers (lowest to highest priority):
    /// 1. Hardcoded defaults via `serde(default)`.
    /// 2. Optional file named `sincerin` (any supported format:
    ///    TOML, JSON, YAML, etc.) in the current directory.
    /// 3. Environment variables prefixed with `SINCERIN_` (underscore-
    ///    separated, e.g. `SINCERIN_NATS_URL`).
    pub fn load() -> Result<Self, config::ConfigError> {
        let settings = config::Config::builder()
            .add_source(config::File::with_name("sincerin").required(false))
            .add_source(config::Environment::with_prefix("SINCERIN").try_parsing(true))
            .build()?;

        settings.try_deserialize()
    }
}

// ---------------------------------------------------------------------------
// Tracing initialisation
// ---------------------------------------------------------------------------

/// Initialise a `tracing` subscriber with the given log level.
///
/// The subscriber uses:
/// - `EnvFilter` for level-based filtering (respects `RUST_LOG` if set,
///   otherwise falls back to `log_level`).
/// - JSON formatting for structured log output (machine-parseable by
///   log aggregation systems like Loki, Datadog, etc.).
///
/// Call this once at process start, before any `tracing::info!()` etc.
pub fn init_tracing(log_level: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Global mutex to serialise tests that touch environment variables.
    // This avoids races when tests run in parallel (`cargo test` default).
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    /// Helper: remove all SINCERIN_ env vars to start clean.
    ///
    /// SAFETY: Tests using this helper are serialised via ENV_MUTEX so
    /// no other thread reads the environment concurrently.
    fn clear_sincerin_env() {
        for (key, _) in std::env::vars() {
            if key.starts_with("SINCERIN_") {
                unsafe { std::env::remove_var(&key) };
            }
        }
    }

    #[test]
    fn test_config_defaults() {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_sincerin_env();

        // SAFETY: serialised via ENV_MUTEX -- no concurrent env access.
        unsafe {
            // Set the three required fields that have no defaults.
            std::env::set_var(
                "SINCERIN_COORDINATOR_ADDRESS",
                "0x0000000000000000000000000000000000000001",
            );
            std::env::set_var(
                "SINCERIN_PROOF_REGISTRY_ADDRESS",
                "0x0000000000000000000000000000000000000002",
            );
            std::env::set_var(
                "SINCERIN_PROVER_REGISTRY_ADDRESS",
                "0x0000000000000000000000000000000000000003",
            );
        }

        let config = CommonConfig::load().expect("should load with required env vars");

        // Verify defaults are applied for fields that were not overridden.
        assert_eq!(config.nats_url, "nats://localhost:4222");
        assert_eq!(
            config.l1_rpc_url,
            "http://localhost:9650/ext/bc/sincerin/rpc"
        );
        assert_eq!(config.l1_ws_url, "ws://localhost:9650/ext/bc/sincerin/ws");
        assert_eq!(config.log_level, "info");
        assert_eq!(config.metrics_port, 9090);
        assert_eq!(config.chain_id, 43214321);

        // Verify required fields were picked up.
        assert_eq!(
            config.coordinator_address,
            "0x0000000000000000000000000000000000000001"
        );
        assert_eq!(
            config.proof_registry_address,
            "0x0000000000000000000000000000000000000002"
        );
        assert_eq!(
            config.prover_registry_address,
            "0x0000000000000000000000000000000000000003"
        );

        // Clean up.
        clear_sincerin_env();
    }

    #[test]
    fn test_config_env_override() {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_sincerin_env();

        // SAFETY: serialised via ENV_MUTEX -- no concurrent env access.
        unsafe {
            // Set required fields.
            std::env::set_var("SINCERIN_COORDINATOR_ADDRESS", "0xcoord");
            std::env::set_var("SINCERIN_PROOF_REGISTRY_ADDRESS", "0xproof");
            std::env::set_var("SINCERIN_PROVER_REGISTRY_ADDRESS", "0xprover");

            // Override optional fields.
            std::env::set_var("SINCERIN_NATS_URL", "nats://custom:4222");
            std::env::set_var("SINCERIN_METRICS_PORT", "9999");
        }

        let config = CommonConfig::load().expect("should load with overrides");

        assert_eq!(config.nats_url, "nats://custom:4222");
        assert_eq!(config.metrics_port, 9999);

        // Fields without overrides should still have defaults.
        assert_eq!(config.log_level, "info");
        assert_eq!(config.chain_id, 43214321);

        // Clean up.
        clear_sincerin_env();
    }
}
