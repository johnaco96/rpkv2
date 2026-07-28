use anyhow::{Result, bail};
use clap::ValueEnum;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum RuntimeMode {
    Demo,
    Benchmark,
    Production,
}

impl fmt::Display for RuntimeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Demo => f.write_str("demo"),
            Self::Benchmark => f.write_str("benchmark"),
            Self::Production => f.write_str("production"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartupGuardrails {
    pub mode: RuntimeMode,
    pub has_config: bool,
    pub generated_ephemeral_keys: bool,
    pub metrics_enabled: bool,
    pub peer_count: usize,
    pub accepted_demo_storage: bool,
}

impl StartupGuardrails {
    pub fn validate(self) -> Result<()> {
        match self.mode {
            RuntimeMode::Production => self.validate_production(),
            RuntimeMode::Demo | RuntimeMode::Benchmark => Ok(()),
        }
    }

    fn validate_production(self) -> Result<()> {
        validate_production_features()?;
        if !self.has_config {
            bail!("production mode requires --config");
        }
        if self.generated_ephemeral_keys {
            bail!("production mode refuses ephemeral generated keys");
        }
        if !self.metrics_enabled {
            bail!("production mode requires metrics to be enabled");
        }
        if self.peer_count == 0 {
            bail!("production mode requires a nonempty peer registry");
        }
        if !self.accepted_demo_storage {
            bail!(
                "production mode requires configured storage durability or explicit storage risk acknowledgement"
            );
        }
        Ok(())
    }
}

#[cfg(not(feature = "ed25519"))]
fn validate_production_features() -> Result<()> {
    bail!("production mode requires the ed25519 feature");
}

#[cfg(all(feature = "ed25519", feature = "insecure_demo"))]
fn validate_production_features() -> Result<()> {
    bail!("production mode cannot run with insecure_demo enabled");
}

#[cfg(all(feature = "ed25519", not(feature = "insecure_demo")))]
fn validate_production_features() -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn production_guardrails() -> StartupGuardrails {
        StartupGuardrails {
            mode: RuntimeMode::Production,
            has_config: true,
            generated_ephemeral_keys: false,
            metrics_enabled: true,
            peer_count: 1,
            accepted_demo_storage: true,
        }
    }

    #[test]
    fn production_mode_accepts_safe_configured_startup() {
        production_guardrails().validate().unwrap();
    }

    #[test]
    fn production_mode_without_config_fails() {
        let mut guardrails = production_guardrails();
        guardrails.has_config = false;

        assert!(guardrails.validate().is_err());
    }

    #[test]
    fn production_mode_with_ephemeral_keys_fails() {
        let mut guardrails = production_guardrails();
        guardrails.generated_ephemeral_keys = true;

        assert!(guardrails.validate().is_err());
    }

    #[test]
    fn production_mode_without_peers_fails() {
        let mut guardrails = production_guardrails();
        guardrails.peer_count = 0;

        assert!(guardrails.validate().is_err());
    }

    #[test]
    fn benchmark_mode_is_explicitly_allowed_without_production_config() {
        StartupGuardrails {
            mode: RuntimeMode::Benchmark,
            has_config: false,
            generated_ephemeral_keys: false,
            metrics_enabled: false,
            peer_count: 0,
            accepted_demo_storage: false,
        }
        .validate()
        .unwrap();
    }
}
