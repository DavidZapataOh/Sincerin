//! Stream configuration factories for Sincerin NATS JetStream.
//!
//! Each function returns a `stream::Config` that can be passed to
//! `jetstream.get_or_create_stream()`. The `replicas` parameter
//! controls replication: use 1 for dev, 3 for production.
//!
//! # Stream architecture
//!
//! Sincerin uses per-topic streams (one stream per logical channel)
//! rather than consolidated wildcard streams. This allows each stream
//! to use the optimal retention policy:
//!
//! | Stream | Retention | Rationale |
//! |--------|-----------|-----------|
//! | PROOF_REQUESTS | WorkQueue | Each request dispatched exactly once |
//! | PROOF_RESULTS | WorkQueue | Each result collected exactly once |
//! | PROOF_TASKS | WorkQueue | Each task consumed by exactly one prover |
//! | PROOF_CLIENT | WorkQueue | Each client proof collected exactly once |
//! | PROOF_STATUS | Limits | Status history retained for WebSocket replay |
//! | PROOF_VERIFIED | Limits | Verified events for gateway + external consumers |
//! | PROVERS | Limits (Memory) | Ephemeral prover lifecycle events |
//! | SYSTEM | Limits (File) | Long-lived operational events |

use std::time::Duration;

use async_nats::jetstream::stream;

use crate::nats::subjects;

// ---------------------------------------------------------------------------
// Proof pipeline streams
// ---------------------------------------------------------------------------

/// Stream config for proof generation requests.
///
/// WorkQueue retention ensures each request is consumed exactly once
/// by the dispatcher.
pub fn proof_requests_config(replicas: usize) -> stream::Config {
    stream::Config {
        name: "PROOF_REQUESTS".to_string(),
        subjects: vec![subjects::PROOF_REQUESTS.to_string()],
        retention: stream::RetentionPolicy::WorkQueue,
        max_age: Duration::from_secs(3600), // 1h
        num_replicas: replicas,
        ..Default::default()
    }
}

/// Stream config for completed proof results.
///
/// WorkQueue retention ensures each result is collected exactly once
/// by the collector service.
pub fn proof_results_config(replicas: usize) -> stream::Config {
    stream::Config {
        name: "PROOF_RESULTS".to_string(),
        subjects: vec![subjects::PROOF_RESULTS.to_string()],
        retention: stream::RetentionPolicy::WorkQueue,
        max_age: Duration::from_secs(3600), // 1h
        num_replicas: replicas,
        ..Default::default()
    }
}

/// Stream config for proof status updates.
///
/// Limits retention keeps a history for WebSocket replay.
/// Wildcard subject allows per-request filtering.
pub fn proof_status_config(replicas: usize) -> stream::Config {
    stream::Config {
        name: "PROOF_STATUS".to_string(),
        subjects: vec![format!("{}.*", subjects::PROOF_STATUS)],
        retention: stream::RetentionPolicy::Limits,
        max_age: Duration::from_secs(86_400), // 24h
        num_replicas: replicas,
        ..Default::default()
    }
}

/// Stream config for prover task assignments.
///
/// WorkQueue retention ensures each task is consumed by exactly one
/// prover node. Wildcard subject allows per-prover filtering.
pub fn proof_tasks_config(replicas: usize) -> stream::Config {
    stream::Config {
        name: "PROOF_TASKS".to_string(),
        subjects: vec![format!("{}.>", subjects::PROOF_TASKS)],
        retention: stream::RetentionPolicy::WorkQueue,
        max_age: Duration::from_secs(3600), // 1h
        num_replicas: replicas,
        ..Default::default()
    }
}

/// Stream config for client-side proving requests.
///
/// WorkQueue retention ensures each client proof is collected exactly
/// once by the collector service.
pub fn proof_client_config(replicas: usize) -> stream::Config {
    stream::Config {
        name: "PROOF_CLIENT".to_string(),
        subjects: vec![subjects::PROOF_CLIENT.to_string()],
        retention: stream::RetentionPolicy::WorkQueue,
        max_age: Duration::from_secs(3600), // 1h
        num_replicas: replicas,
        ..Default::default()
    }
}

/// Stream config for verified proof events.
///
/// Limits retention keeps verified events for gateway WebSocket
/// notifications and external consumer subscriptions.
pub fn proof_verified_config(replicas: usize) -> stream::Config {
    stream::Config {
        name: "PROOF_VERIFIED".to_string(),
        subjects: vec![subjects::PROOF_VERIFIED.to_string()],
        retention: stream::RetentionPolicy::Limits,
        max_age: Duration::from_secs(86_400), // 24h
        num_replicas: replicas,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Prover management stream
// ---------------------------------------------------------------------------

/// Stream config for prover lifecycle events (heartbeats, register, deregister).
///
/// Memory-backed with short TTL since these events are ephemeral.
pub fn provers_config(replicas: usize) -> stream::Config {
    stream::Config {
        name: "PROVERS".to_string(),
        subjects: vec!["sincerin.provers.>".to_string()],
        storage: stream::StorageType::Memory,
        retention: stream::RetentionPolicy::Limits,
        max_messages: 10_000,
        max_age: Duration::from_secs(3600), // 1h
        discard: stream::DiscardPolicy::Old,
        num_replicas: replicas,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// System stream
// ---------------------------------------------------------------------------

/// Stream config for system-wide metrics and alert events.
///
/// File-backed with longer retention for operational observability.
pub fn system_config(replicas: usize) -> stream::Config {
    stream::Config {
        name: "SYSTEM".to_string(),
        subjects: vec!["sincerin.system.>".to_string()],
        storage: stream::StorageType::File,
        retention: stream::RetentionPolicy::Limits,
        max_messages: 50_000,
        max_age: Duration::from_secs(604_800), // 7d
        discard: stream::DiscardPolicy::Old,
        num_replicas: replicas,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_requests_stream_config() {
        let cfg = proof_requests_config(1);
        assert_eq!(cfg.name, "PROOF_REQUESTS");
        assert_eq!(cfg.subjects, vec!["sincerin.proofs.requests"]);
        assert_eq!(cfg.retention, stream::RetentionPolicy::WorkQueue);
        assert_eq!(cfg.max_age, Duration::from_secs(3600));
        assert_eq!(cfg.num_replicas, 1);
    }

    #[test]
    fn test_proof_status_stream_config() {
        let cfg = proof_status_config(1);
        assert_eq!(cfg.name, "PROOF_STATUS");
        assert_eq!(cfg.subjects, vec!["sincerin.proofs.status.*"]);
        assert_eq!(cfg.retention, stream::RetentionPolicy::Limits);
        assert_eq!(cfg.max_age, Duration::from_secs(86_400));
    }

    #[test]
    fn test_provers_stream_config() {
        let cfg = provers_config(1);
        assert_eq!(cfg.name, "PROVERS");
        assert_eq!(cfg.storage, stream::StorageType::Memory);
        assert_eq!(cfg.max_age, Duration::from_secs(3600));
        assert_eq!(cfg.max_messages, 10_000);
    }

    #[test]
    fn test_system_stream_config() {
        let cfg = system_config(1);
        assert_eq!(cfg.name, "SYSTEM");
        assert_eq!(cfg.storage, stream::StorageType::File);
        assert_eq!(cfg.max_age, Duration::from_secs(604_800));
        assert_eq!(cfg.max_messages, 50_000);
    }

    #[test]
    fn test_stream_config_replicas() {
        let cfg = proof_requests_config(3);
        assert_eq!(cfg.num_replicas, 3);

        let cfg = provers_config(3);
        assert_eq!(cfg.num_replicas, 3);
    }

    #[test]
    fn test_proof_tasks_stream_config() {
        let cfg = proof_tasks_config(1);
        assert_eq!(cfg.name, "PROOF_TASKS");
        assert_eq!(cfg.subjects, vec!["sincerin.proofs.tasks.>"]);
        assert_eq!(cfg.retention, stream::RetentionPolicy::WorkQueue);
    }

    #[test]
    fn test_proof_verified_stream_config() {
        let cfg = proof_verified_config(1);
        assert_eq!(cfg.name, "PROOF_VERIFIED");
        assert_eq!(cfg.subjects, vec!["sincerin.proofs.verified"]);
        assert_eq!(cfg.retention, stream::RetentionPolicy::Limits);
        assert_eq!(cfg.max_age, Duration::from_secs(86_400));
    }
}
