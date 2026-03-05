//! Consumer configuration factories for Sincerin NATS JetStream.
//!
//! Each function returns a consumer config that can be passed to
//! `stream.get_or_create_consumer()`. This centralizes consumer
//! definitions that were previously hardcoded in each service.
//!
//! # Consumer behavior matrix
//!
//! | Consumer | Type | Stream | Filter | On success | On retryable | On non-retryable |
//! |---|---|---|---|---|---|---|
//! | dispatcher | Pull | PROOF_REQUESTS | requests | ack | nack (3x) | ack (discard) |
//! | prover-{id} | Pull | PROOF_TASKS | tasks.{id} | ack | nack (3x) | ack (discard) |
//! | collector-results | Pull | PROOF_RESULTS | results | ack | nack (3x) | ack (discard) |
//! | collector-client | Pull | PROOF_CLIENT | client | ack | nack (3x) | ack (discard) |
//! | gateway-status | Push | PROOF_STATUS | status.* | auto-ack | N/A | N/A |
//! | gateway-verified | Push | PROOF_VERIFIED | verified | auto-ack | N/A | N/A |

use std::time::Duration;

use async_nats::jetstream::consumer;

use crate::nats::subjects;

// ---------------------------------------------------------------------------
// Pull consumers (durable, explicit ack)
// ---------------------------------------------------------------------------

/// Dispatcher consumer config — consumes proof requests.
///
/// Ack wait: 30s (dispatch is fast, no heavy computation).
pub fn dispatcher_config() -> consumer::pull::Config {
    consumer::pull::Config {
        durable_name: Some("dispatcher".to_string()),
        filter_subject: subjects::PROOF_REQUESTS.to_string(),
        ack_policy: consumer::AckPolicy::Explicit,
        deliver_policy: consumer::DeliverPolicy::All,
        max_deliver: 3,
        ack_wait: Duration::from_secs(30),
        ..Default::default()
    }
}

/// Prover consumer config — consumes tasks assigned to a specific prover.
///
/// Ack wait: 120s (proof generation can take several seconds).
pub fn prover_config(prover_id: &str) -> consumer::pull::Config {
    consumer::pull::Config {
        durable_name: Some(format!("prover-{prover_id}")),
        filter_subject: subjects::proof_tasks(prover_id),
        ack_policy: consumer::AckPolicy::Explicit,
        deliver_policy: consumer::DeliverPolicy::All,
        max_deliver: 3,
        ack_wait: Duration::from_secs(120),
        ..Default::default()
    }
}

/// Collector results consumer config — consumes completed proof results.
///
/// Ack wait: 60s (L1 verification may take time).
pub fn collector_results_config() -> consumer::pull::Config {
    consumer::pull::Config {
        durable_name: Some("collector-results".to_string()),
        filter_subject: subjects::PROOF_RESULTS.to_string(),
        ack_policy: consumer::AckPolicy::Explicit,
        deliver_policy: consumer::DeliverPolicy::All,
        max_deliver: 3,
        ack_wait: Duration::from_secs(60),
        ..Default::default()
    }
}

/// Collector client consumer config — consumes client-side proofs.
///
/// Ack wait: 60s (L1 verification may take time).
pub fn collector_client_config() -> consumer::pull::Config {
    consumer::pull::Config {
        durable_name: Some("collector-client".to_string()),
        filter_subject: subjects::PROOF_CLIENT.to_string(),
        ack_policy: consumer::AckPolicy::Explicit,
        deliver_policy: consumer::DeliverPolicy::All,
        max_deliver: 3,
        ack_wait: Duration::from_secs(60),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Push consumers (ephemeral, auto-ack for real-time delivery)
// ---------------------------------------------------------------------------

/// Gateway status consumer config — receives real-time status updates.
///
/// Uses `DeliverPolicy::New` so only messages published after
/// subscription are delivered (no replay of old status events).
/// `AckPolicy::None` means messages are auto-acknowledged.
pub fn gateway_status_config(deliver_subject: &str) -> consumer::push::Config {
    consumer::push::Config {
        durable_name: Some("gateway-status".to_string()),
        deliver_subject: deliver_subject.to_string(),
        filter_subject: format!("{}.*", subjects::PROOF_STATUS),
        ack_policy: consumer::AckPolicy::None,
        deliver_policy: consumer::DeliverPolicy::New,
        max_deliver: 1,
        ..Default::default()
    }
}

/// Gateway verified consumer config — receives verified proof events.
///
/// Same semantics as gateway-status: new messages only, auto-ack.
pub fn gateway_verified_config(deliver_subject: &str) -> consumer::push::Config {
    consumer::push::Config {
        durable_name: Some("gateway-verified".to_string()),
        deliver_subject: deliver_subject.to_string(),
        filter_subject: subjects::PROOF_VERIFIED.to_string(),
        ack_policy: consumer::AckPolicy::None,
        deliver_policy: consumer::DeliverPolicy::New,
        max_deliver: 1,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dispatcher_consumer_config() {
        let cfg = dispatcher_config();
        assert_eq!(cfg.durable_name.as_deref(), Some("dispatcher"));
        assert_eq!(cfg.filter_subject, "sincerin.proofs.requests");
        assert_eq!(cfg.ack_policy, consumer::AckPolicy::Explicit);
        assert_eq!(cfg.deliver_policy, consumer::DeliverPolicy::All);
        assert_eq!(cfg.max_deliver, 3);
        assert_eq!(cfg.ack_wait, Duration::from_secs(30));
    }

    #[test]
    fn test_prover_consumer_config() {
        let cfg = prover_config("prover-01");
        assert_eq!(cfg.durable_name.as_deref(), Some("prover-prover-01"));
        assert_eq!(cfg.filter_subject, "sincerin.proofs.tasks.prover-01");
        assert_eq!(cfg.ack_policy, consumer::AckPolicy::Explicit);
        assert_eq!(cfg.ack_wait, Duration::from_secs(120));
    }

    #[test]
    fn test_prover_consumer_dynamic_creation() {
        let cfg1 = prover_config("prover-01");
        let cfg2 = prover_config("prover-02");
        assert_ne!(
            cfg1.durable_name, cfg2.durable_name,
            "Different provers should have different consumer names"
        );
        assert_ne!(
            cfg1.filter_subject, cfg2.filter_subject,
            "Different provers should filter different subjects"
        );
    }

    #[test]
    fn test_collector_results_consumer_config() {
        let cfg = collector_results_config();
        assert_eq!(cfg.durable_name.as_deref(), Some("collector-results"));
        assert_eq!(cfg.filter_subject, "sincerin.proofs.results");
        assert_eq!(cfg.ack_policy, consumer::AckPolicy::Explicit);
        assert_eq!(cfg.max_deliver, 3);
        assert_eq!(cfg.ack_wait, Duration::from_secs(60));
    }

    #[test]
    fn test_collector_client_consumer_config() {
        let cfg = collector_client_config();
        assert_eq!(cfg.durable_name.as_deref(), Some("collector-client"));
        assert_eq!(cfg.filter_subject, "sincerin.proofs.client");
        assert_eq!(cfg.ack_policy, consumer::AckPolicy::Explicit);
        assert_eq!(cfg.ack_wait, Duration::from_secs(60));
    }

    #[test]
    fn test_gateway_status_consumer_config() {
        let cfg = gateway_status_config("_INBOX.ws.test123");
        assert_eq!(cfg.durable_name.as_deref(), Some("gateway-status"));
        assert_eq!(cfg.deliver_subject, "_INBOX.ws.test123");
        assert_eq!(cfg.filter_subject, "sincerin.proofs.status.*");
        assert_eq!(cfg.ack_policy, consumer::AckPolicy::None);
        assert_eq!(cfg.deliver_policy, consumer::DeliverPolicy::New);
        assert_eq!(cfg.max_deliver, 1);
    }

    #[test]
    fn test_gateway_verified_consumer_config() {
        let cfg = gateway_verified_config("_INBOX.ws.test456");
        assert_eq!(cfg.durable_name.as_deref(), Some("gateway-verified"));
        assert_eq!(cfg.filter_subject, "sincerin.proofs.verified");
        assert_eq!(cfg.ack_policy, consumer::AckPolicy::None);
        assert_eq!(cfg.deliver_policy, consumer::DeliverPolicy::New);
    }
}
