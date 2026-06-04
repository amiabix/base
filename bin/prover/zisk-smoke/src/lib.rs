#![doc = include_str!("../README.md")]

mod config;
pub use config::SmokeConfig;

mod runner;
pub use runner::{SmokeRunOutput, SmokeRunner};
