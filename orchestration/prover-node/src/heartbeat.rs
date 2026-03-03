use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_nats::jetstream::Context as JetStream;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Prover operational status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProverNodeStatus {
    Idle = 0,
    Proving = 1,
    Draining = 2,
    Error = 3,
}

impl From<u8> for ProverNodeStatus {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Idle,
            1 => Self::Proving,
            2 => Self::Draining,
            3 => Self::Error,
            _ => Self::Error,
        }
    }
}

/// Hardware information reported in heartbeats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareInfo {
    pub cpu_cores: u32,
    pub memory_total_mb: u64,
    pub memory_available_mb: u64,
}

impl HardwareInfo {
    /// Collect hardware information from the system.
    /// Falls back to defaults if collection fails.
    pub fn collect() -> Self {
        let cpu_cores = std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(0);

        // On macOS/Linux, we'd use sysinfo crate for memory.
        // For MVP, report 0 (unknown) — avoids adding sysinfo dependency.
        Self {
            cpu_cores,
            memory_total_mb: 0,
            memory_available_mb: 0,
        }
    }
}

/// Heartbeat message published periodically to NATS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatMessage {
    pub prover_id: String,
    pub status: ProverNodeStatus,
    pub current_load: f64,
    pub active_proofs: u32,
    pub max_concurrent: u32,
    pub uptime_secs: u64,
    pub hardware: HardwareInfo,
    pub timestamp: String,
}

/// Shared state between the executor and heartbeat service.
pub struct SharedState {
    pub status: AtomicU8,
    pub active_proofs: AtomicU32,
}

impl SharedState {
    pub fn new() -> Self {
        Self {
            status: AtomicU8::new(ProverNodeStatus::Idle as u8),
            active_proofs: AtomicU32::new(0),
        }
    }

    pub fn set_status(&self, status: ProverNodeStatus) {
        self.status.store(status as u8, Ordering::Relaxed);
    }

    pub fn get_status(&self) -> ProverNodeStatus {
        ProverNodeStatus::from(self.status.load(Ordering::Relaxed))
    }

    pub fn increment_active(&self) {
        self.active_proofs.fetch_add(1, Ordering::Relaxed);
        self.set_status(ProverNodeStatus::Proving);
    }

    pub fn decrement_active(&self) {
        let prev = self.active_proofs.fetch_sub(1, Ordering::Relaxed);
        if prev <= 1 {
            self.set_status(ProverNodeStatus::Idle);
        }
    }
}

impl Default for SharedState {
    fn default() -> Self {
        Self::new()
    }
}

/// Periodic heartbeat publisher.
pub struct HeartbeatService {
    js: JetStream,
    prover_id: String,
    interval: Duration,
    shared_state: Arc<SharedState>,
    max_concurrent: u32,
    start_time: Instant,
}

impl HeartbeatService {
    pub fn new(
        js: JetStream,
        prover_id: String,
        interval: Duration,
        shared_state: Arc<SharedState>,
        max_concurrent: u32,
    ) -> Self {
        Self {
            js,
            prover_id,
            interval,
            shared_state,
            max_concurrent,
            start_time: Instant::now(),
        }
    }

    /// Run the heartbeat loop until the cancellation token fires.
    pub async fn run(&self, cancel: CancellationToken) {
        let mut ticker = tokio::time::interval(self.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        info!(
            prover_id = %self.prover_id,
            interval_secs = self.interval.as_secs(),
            "Heartbeat service started"
        );

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("Heartbeat service shutting down");
                    break;
                }
                _ = ticker.tick() => {
                    self.send_heartbeat().await;
                }
            }
        }
    }

    async fn send_heartbeat(&self) {
        let active = self.shared_state.active_proofs.load(Ordering::Relaxed);
        let status = self.shared_state.get_status();
        let load = if self.max_concurrent > 0 {
            active as f64 / self.max_concurrent as f64
        } else {
            0.0
        };

        let message = HeartbeatMessage {
            prover_id: self.prover_id.clone(),
            status,
            current_load: load,
            active_proofs: active,
            max_concurrent: self.max_concurrent,
            uptime_secs: self.start_time.elapsed().as_secs(),
            hardware: HardwareInfo::collect(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let subject = sincerin_common::nats::subjects::PROVER_HEARTBEAT;
        match serde_json::to_vec(&message) {
            Ok(payload) => {
                // Use core NATS publish (not JetStream) — heartbeats are ephemeral
                if let Err(e) = self
                    .js
                    .publish(subject.to_string(), payload.into())
                    .await
                {
                    warn!(error = %e, "Failed to publish heartbeat");
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to serialize heartbeat");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_state_defaults() {
        let state = SharedState::new();
        assert_eq!(state.get_status(), ProverNodeStatus::Idle);
        assert_eq!(state.active_proofs.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_shared_state_increment_decrement() {
        let state = SharedState::new();

        state.increment_active();
        assert_eq!(state.get_status(), ProverNodeStatus::Proving);
        assert_eq!(state.active_proofs.load(Ordering::Relaxed), 1);

        state.decrement_active();
        assert_eq!(state.get_status(), ProverNodeStatus::Idle);
        assert_eq!(state.active_proofs.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_prover_status_from_u8() {
        assert_eq!(ProverNodeStatus::from(0), ProverNodeStatus::Idle);
        assert_eq!(ProverNodeStatus::from(1), ProverNodeStatus::Proving);
        assert_eq!(ProverNodeStatus::from(2), ProverNodeStatus::Draining);
        assert_eq!(ProverNodeStatus::from(3), ProverNodeStatus::Error);
        assert_eq!(ProverNodeStatus::from(255), ProverNodeStatus::Error);
    }

    #[test]
    fn test_hardware_info_collect() {
        let info = HardwareInfo::collect();
        // CPU cores should be at least 1 on any real system
        assert!(info.cpu_cores >= 1, "Should detect at least 1 CPU core");
    }

    #[test]
    fn test_heartbeat_message_serialization() {
        let msg = HeartbeatMessage {
            prover_id: "prover-01".to_string(),
            status: ProverNodeStatus::Idle,
            current_load: 0.0,
            active_proofs: 0,
            max_concurrent: 1,
            uptime_secs: 60,
            hardware: HardwareInfo {
                cpu_cores: 8,
                memory_total_mb: 16384,
                memory_available_mb: 8192,
            },
            timestamp: "2024-03-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("prover-01"));
        assert!(json.contains("idle"));

        // Verify round-trip
        let deserialized: HeartbeatMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.prover_id, "prover-01");
        assert_eq!(deserialized.status, ProverNodeStatus::Idle);
    }
}
