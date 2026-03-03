use std::collections::HashSet;

/// Gateway-specific configuration.
///
/// Loaded from environment variables with `SINCERIN_GATEWAY_` prefix,
/// falling back to hardcoded defaults.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub host: String,
    pub port: u16,
    pub nats_url: String,
    pub metrics_port: u16,
    pub api_keys: HashSet<String>,
    pub rate_limit_rps: u32,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 3000,
            nats_url: "nats://localhost:4222".to_string(),
            metrics_port: 9090,
            api_keys: HashSet::new(),
            rate_limit_rps: 100,
        }
    }
}

impl GatewayConfig {
    /// Load configuration from environment variables.
    ///
    /// Environment variables:
    /// - `SINCERIN_GATEWAY_HOST` (default: "0.0.0.0")
    /// - `SINCERIN_GATEWAY_PORT` (default: 3000)
    /// - `SINCERIN_GATEWAY_NATS_URL` (default: "nats://localhost:4222")
    /// - `SINCERIN_GATEWAY_METRICS_PORT` (default: 9090)
    /// - `SINCERIN_GATEWAY_API_KEYS` (comma-separated, default: empty)
    /// - `SINCERIN_GATEWAY_RATE_LIMIT_RPS` (default: 100)
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(host) = std::env::var("SINCERIN_GATEWAY_HOST") {
            config.host = host;
        }
        if let Ok(port) = std::env::var("SINCERIN_GATEWAY_PORT")
            && let Ok(p) = port.parse()
        {
            config.port = p;
        }
        if let Ok(nats_url) = std::env::var("SINCERIN_GATEWAY_NATS_URL") {
            config.nats_url = nats_url;
        }
        if let Ok(metrics_port) = std::env::var("SINCERIN_GATEWAY_METRICS_PORT")
            && let Ok(p) = metrics_port.parse()
        {
            config.metrics_port = p;
        }
        if let Ok(keys) = std::env::var("SINCERIN_GATEWAY_API_KEYS") {
            config.api_keys = keys
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Ok(rps) = std::env::var("SINCERIN_GATEWAY_RATE_LIMIT_RPS")
            && let Ok(r) = rps.parse()
        {
            config.rate_limit_rps = r;
        }

        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = GatewayConfig::default();
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.port, 3000);
        assert_eq!(config.nats_url, "nats://localhost:4222");
        assert_eq!(config.metrics_port, 9090);
        assert!(config.api_keys.is_empty());
        assert_eq!(config.rate_limit_rps, 100);
    }

    #[test]
    fn test_config_from_env() {
        // SAFETY: test-only, single-threaded test runner
        unsafe {
            std::env::set_var("SINCERIN_GATEWAY_HOST", "127.0.0.1");
            std::env::set_var("SINCERIN_GATEWAY_PORT", "8080");
            std::env::set_var("SINCERIN_GATEWAY_API_KEYS", "key1,key2,key3");
            std::env::set_var("SINCERIN_GATEWAY_RATE_LIMIT_RPS", "200");
        }

        let config = GatewayConfig::from_env();
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 8080);
        assert_eq!(config.api_keys.len(), 3);
        assert!(config.api_keys.contains("key1"));
        assert!(config.api_keys.contains("key2"));
        assert!(config.api_keys.contains("key3"));
        assert_eq!(config.rate_limit_rps, 200);

        // Cleanup
        unsafe {
            std::env::remove_var("SINCERIN_GATEWAY_HOST");
            std::env::remove_var("SINCERIN_GATEWAY_PORT");
            std::env::remove_var("SINCERIN_GATEWAY_API_KEYS");
            std::env::remove_var("SINCERIN_GATEWAY_RATE_LIMIT_RPS");
        }
    }
}
