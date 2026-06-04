/// Tracing setup for native range guest runs.
#[derive(Debug, Clone, Copy)]
pub struct RangeTracing;

impl RangeTracing {
    /// Install a tracing subscriber for native debugging runs.
    pub fn setup() {
        let subscriber = tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).finish();
        tracing::subscriber::set_global_default(subscriber)
            .map_err(|err| anyhow::anyhow!(err))
            .expect("failed to install range guest tracing subscriber");
    }
}
