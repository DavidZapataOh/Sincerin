use std::path::PathBuf;

use serde::Deserialize;

fn default_prover_id() -> String {
    "prover-01".to_string()
}

fn default_nats_url() -> String {
    "nats://localhost:4222".to_string()
}

fn default_bb_binary_path() -> PathBuf {
    PathBuf::from("/tmp/bb")
}

fn default_circuits_dir() -> PathBuf {
    PathBuf::from("./circuits")
}

fn default_work_dir() -> PathBuf {
    PathBuf::from("/tmp/sincerin-prover")
}

fn default_max_concurrent_proofs() -> usize {
    1
}

fn default_heartbeat_interval_secs() -> u64 {
    30
}

fn default_metrics_port() -> u16 {
    9092
}

/// Configuration for the Prover Node service.
#[derive(Debug, Clone, Deserialize)]
pub struct ProverConfig {
    /// Unique prover identifier for task routing and heartbeats.
    #[serde(default = "default_prover_id")]
    pub prover_id: String,

    /// NATS server URL.
    #[serde(default = "default_nats_url")]
    pub nats_url: String,

    /// Path to the Barretenberg (`bb`) CLI binary.
    #[serde(default = "default_bb_binary_path")]
    pub bb_binary_path: PathBuf,

    /// Directory containing compiled circuits (ACIR bytecode + VK).
    #[serde(default = "default_circuits_dir")]
    pub circuits_dir: PathBuf,

    /// Working directory for temporary proof files.
    #[serde(default = "default_work_dir")]
    pub work_dir: PathBuf,

    /// Maximum concurrent proof generations (MVP: 1).
    #[serde(default = "default_max_concurrent_proofs")]
    pub max_concurrent_proofs: usize,

    /// Heartbeat interval in seconds.
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,

    /// Port for the Prometheus metrics exporter.
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            prover_id: default_prover_id(),
            nats_url: default_nats_url(),
            bb_binary_path: default_bb_binary_path(),
            circuits_dir: default_circuits_dir(),
            work_dir: default_work_dir(),
            max_concurrent_proofs: default_max_concurrent_proofs(),
            heartbeat_interval_secs: default_heartbeat_interval_secs(),
            metrics_port: default_metrics_port(),
        }
    }
}

impl ProverConfig {
    /// Load configuration from environment variables prefixed with
    /// `SINCERIN_PROVER_`.
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(v) = std::env::var("SINCERIN_PROVER_ID") {
            config.prover_id = v;
        }
        if let Ok(v) = std::env::var("SINCERIN_PROVER_NATS_URL") {
            config.nats_url = v;
        }
        if let Ok(v) = std::env::var("SINCERIN_PROVER_BB_PATH") {
            config.bb_binary_path = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("SINCERIN_PROVER_CIRCUITS_DIR") {
            config.circuits_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("SINCERIN_PROVER_WORK_DIR") {
            config.work_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("SINCERIN_PROVER_MAX_CONCURRENT")
            && let Ok(n) = v.parse()
        {
            config.max_concurrent_proofs = n;
        }
        if let Ok(v) = std::env::var("SINCERIN_PROVER_HEARTBEAT_INTERVAL")
            && let Ok(n) = v.parse()
        {
            config.heartbeat_interval_secs = n;
        }
        if let Ok(v) = std::env::var("SINCERIN_PROVER_METRICS_PORT")
            && let Ok(n) = v.parse()
        {
            config.metrics_port = n;
        }

        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = ProverConfig::default();
        assert_eq!(config.prover_id, "prover-01");
        assert_eq!(config.nats_url, "nats://localhost:4222");
        assert_eq!(config.bb_binary_path, PathBuf::from("/tmp/bb"));
        assert_eq!(config.circuits_dir, PathBuf::from("./circuits"));
        assert_eq!(config.work_dir, PathBuf::from("/tmp/sincerin-prover"));
        assert_eq!(config.max_concurrent_proofs, 1);
        assert_eq!(config.heartbeat_interval_secs, 30);
        assert_eq!(config.metrics_port, 9092);
    }

    #[test]
    fn test_config_from_env() {
        unsafe {
            std::env::set_var("SINCERIN_PROVER_ID", "prover-99");
            std::env::set_var("SINCERIN_PROVER_BB_PATH", "/opt/bb");
            std::env::set_var("SINCERIN_PROVER_MAX_CONCURRENT", "4");
        }

        let config = ProverConfig::from_env();
        assert_eq!(config.prover_id, "prover-99");
        assert_eq!(config.bb_binary_path, PathBuf::from("/opt/bb"));
        assert_eq!(config.max_concurrent_proofs, 4);

        unsafe {
            std::env::remove_var("SINCERIN_PROVER_ID");
            std::env::remove_var("SINCERIN_PROVER_BB_PATH");
            std::env::remove_var("SINCERIN_PROVER_MAX_CONCURRENT");
        }
    }

    #[test]
    fn test_config_invalid_parse_uses_default() {
        unsafe {
            std::env::set_var("SINCERIN_PROVER_METRICS_PORT", "not-a-number");
        }

        let config = ProverConfig::from_env();
        // Invalid parse should fall back to default
        assert_eq!(config.metrics_port, 9092);

        unsafe {
            std::env::remove_var("SINCERIN_PROVER_METRICS_PORT");
        }
    }
}
