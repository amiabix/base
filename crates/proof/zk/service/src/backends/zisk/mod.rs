//! `ZisK` (Polygon zkVM) proving backend.
//!
//! Embedded prover, deterministic mock, and a witness-generation provider that
//! turns a block range into the rkyv blob the `ZisK` range guest consumes.
//! Gated behind the `zisk` cargo feature.

mod embedded;
pub use embedded::EmbeddedBackend;

mod mock;
pub use mock::MockBackend;

mod provider;
pub use provider::{WitnessParams, ZiskProvider};

mod stats;
pub use stats::StoredExecutionStats as ZiskStoredExecutionStats;
