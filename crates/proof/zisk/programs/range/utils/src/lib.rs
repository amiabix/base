#![doc = include_str!("../README.md")]

extern crate alloc;

mod program;
pub use program::RangeProgram;

#[cfg(feature = "tracing-subscriber")]
mod tracing;
#[cfg(feature = "tracing-subscriber")]
pub use tracing::RangeTracing;
