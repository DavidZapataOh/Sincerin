//! Shared type definitions for the Sincerin orchestration layer.
//!
//! Every type in this module is serializable (serde) and designed for
//! transport over NATS JetStream, REST, and WebSocket channels.
//! Enums use snake_case serialization to match the wire format
//! expected by the Client SDK and the L1 contracts.

pub mod circuit;
pub mod privacy;
pub mod proof_request;
pub mod prover;

pub use circuit::*;
pub use privacy::*;
pub use proof_request::*;
pub use prover::*;
