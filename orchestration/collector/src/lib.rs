//! Sincerin Collector — proof verification and on-chain registration.
//!
//! The Collector is the bridge between the off-chain proving pipeline
//! and the Sincerin L1. It consumes completed proofs from NATS,
//! submits them to `Coordinator.sol` for verification (via the
//! VerifyUltraHonk precompile at ~20K gas), and registers them in
//! `ProofRegistry.sol` (via MerkleTreeInsert precompile at ~500 gas).
//!
//! # Architecture
//!
//! ```text
//! NATS (sincerin.proofs.results)  ──┐
//!                                   ├──► Collector ──► Coordinator.sol ──► L1 Precompiles
//! NATS (sincerin.proofs.client)  ───┘       │
//!                                           └──► NATS (status updates) ──► Gateway (WebSocket)
//! ```
//!
//! # Modules
//!
//! - [`config`] — Collector-specific configuration
//! - [`errors`] — Error types with retryable classification
//! - [`metrics`] — Prometheus metrics for collector operations
//! - [`consumer`] — NATS pull consumers for proof results and client proofs
//! - [`l1_verifier`] — Signed L1 transaction submission to Coordinator.sol
//! - [`registry`] — Read-only ProofRegistry queries
//! - [`collector`] — Core verify-then-register business logic

pub mod collector;
pub mod config;
pub mod consumer;
pub mod errors;
pub mod l1_verifier;
pub mod metrics;
pub mod registry;
