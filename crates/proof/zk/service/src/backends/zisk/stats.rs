//! Execution-stats payload stored alongside `ZisK` proof requests.

use serde::{Deserialize, Serialize};

/// Per-request execution stats captured from the `ZisK` emulator.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoredExecutionStats {
    /// Total instruction cycles executed by the `ZisK` emulator.
    pub cycles: u64,
    /// Executor step count.
    pub steps: u64,
    /// Witness generation duration in milliseconds.
    pub witness_gen_ms: f64,
    /// End-to-end proving wall-clock in milliseconds.
    pub proving_ms: f64,
}

impl StoredExecutionStats {
    /// Construct stats from measured numbers.
    pub const fn new(cycles: u64, steps: u64, witness_gen_ms: f64, proving_ms: f64) -> Self {
        Self { cycles, steps, witness_gen_ms, proving_ms }
    }
}
