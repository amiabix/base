//! Binary entry point for the Base ZisK smoke harness.

use anyhow::Result;
use base_zisk_smoke::{SmokeConfig, SmokeRunner};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).init();

    let output = SmokeRunner::run(SmokeConfig::from_env()?).await?;
    println!(
        "OK witness_ms={:.0} setup_ms={:.0} prove_ms={:.0} total_ms={:.0} receipt_bytes={}",
        output.witness_ms, output.setup_ms, output.prove_ms, output.total_ms, output.receipt_bytes,
    );
    Ok(())
}
